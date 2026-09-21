"""The host-agnostic probes: `scripts.probes.common` (#1627 split these out
of tests/test_host_probes.py; the tests themselves are unchanged)."""
import os
import tempfile
import threading
import unittest
from unittest import mock

from scripts import hosts
import scripts.probes.common as probes_common
from tests.probes.helpers import _shell


class TestRegisteredShellToolsProbe(unittest.TestCase):
    """#1344 F3a: proves the host really registered the shells it claims."""

    def _fully_registered(self, directory):
        from scripts import dispatch
        for role in probes_common.DRIVER_ROLES:
            role_file = dispatch.ROLE_FILES[role]
            allowed = dispatch.load_template(role_file)[0]["tool_policy"]["allowed"]
            _shell(directory, dispatch.registered_agent_filename("claude", role_file),
                   allowed)

    def test_the_driver_roles_are_every_role_the_driver_dispatches(self):
        # #1606: `advisor` was excluded on the claim that the host, not the
        # driver, dispatches it. False -- phases/verify.py::_tool_verify_entry
        # writes a driver entry with agent=panopticon-advisor whenever
        # tool_policy_enforced is PROVEN, a proof this probe established from
        # the OTHER three shells. Derived from ROLE_FILES so no hand-kept
        # tuple can quietly leave a dispatched role unchecked again.
        from scripts import dispatch
        self.assertEqual(tuple(sorted(dispatch.ROLE_FILES)), probes_common.DRIVER_ROLES)
        self.assertIn("advisor", probes_common.DRIVER_ROLES)

    def test_a_missing_advisor_shell_is_refuted(self):
        # The fixture #1606 is about: three perfect shells, no advisor shell.
        # Before the fix this was PROVEN and tool-verify dispatched
        # panopticon-advisor enforced into a shell that did not exist.
        from scripts import dispatch
        with tempfile.TemporaryDirectory() as d:
            self._fully_registered(d)
            os.remove(os.path.join(
                d, dispatch.registered_agent_filename("claude", "advisor.md")))
            state, _by, detail = probes_common.probe_registered_shell_tools("claude", d)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("advisor: no shell at", detail)

    def test_a_complete_correct_registration_is_proven(self):
        with tempfile.TemporaryDirectory() as d:
            self._fully_registered(d)
            state, by, detail = probes_common.probe_registered_shell_tools("claude", d)
            self.assertEqual(hosts.PROVEN, state)
            self.assertEqual("registered-shell-tools", by)
            self.assertIn("%d/%d" % (len(probes_common.DRIVER_ROLES),
                                     len(probes_common.DRIVER_ROLES)), detail)

    def test_the_setup_scan_shell_is_checked_and_grants_no_bash(self):
        # #1737, brief case (e): `registered-shell-tools` is the proof
        # read_guard_hook.py cites for "No fan-out shell grants Bash" -- a
        # premise that held only for REGISTERED roles, and therefore not for
        # the one dispatch that reads the whole untrusted tree. The verdict is
        # unchanged with the new shell present, and a setup-scan shell that
        # grants Bash now refutes exactly like any other role's would.
        from scripts import dispatch
        self.assertIn("setup_scan", probes_common.DRIVER_ROLES)
        role_file = dispatch.ROLE_FILES["setup_scan"]
        with tempfile.TemporaryDirectory() as d:
            self._fully_registered(d)
            state, _by, detail = probes_common.probe_registered_shell_tools("claude", d)
            self.assertEqual(hosts.PROVEN, state)
            self.assertNotIn("Bash", detail)
            _shell(d, dispatch.registered_agent_filename("claude", role_file),
                   ["Read", "Grep", "Glob", "Bash"])
            state, _by, detail = probes_common.probe_registered_shell_tools("claude", d)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("setup_scan: shell grants forbidden tool(s) Bash", detail)

    def test_an_empty_registration_dir_is_refuted(self):
        # THE negative fixture. This is the 7.1 case: a Claude run whose
        # shells were never registered must stop claiming enforcement.
        with tempfile.TemporaryDirectory() as d:
            state, _by, detail = probes_common.probe_registered_shell_tools("claude", d)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn("scout", detail)

    def test_one_missing_role_is_refuted_and_named(self):
        from scripts import dispatch
        with tempfile.TemporaryDirectory() as d:
            self._fully_registered(d)
            os.remove(os.path.join(d, dispatch.registered_agent_filename(
                "claude", dispatch.ROLE_FILES["domain_panel"])))
            state, _by, detail = probes_common.probe_registered_shell_tools("claude", d)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn("domain_panel", detail)

    def test_a_shell_granting_a_forbidden_tool_is_refuted(self):
        # This branch changes the MESSAGE, not the VERDICT. Because allowed and
        # forbidden are disjoint in every template, the equality check would
        # refute this shell anyway. The branch exists so an operator reading
        # spec 7.1's refusal learns that a FORBIDDEN tool leaked into a
        # registered shell, rather than being handed two lists to diff by eye.
        from scripts import dispatch
        with tempfile.TemporaryDirectory() as d:
            self._fully_registered(d)
            _shell(d, dispatch.registered_agent_filename(
                "claude", dispatch.ROLE_FILES["scout"]),
                ["Read", "Grep", "Glob", "Bash"])
            state, _by, detail = probes_common.probe_registered_shell_tools("claude", d)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn("scout", detail)
            # The token that ONLY the forbidden branch emits. Asserting on
            # "Bash" instead would pass either way: allowed and forbidden are
            # disjoint, so a forbidden grant also trips the equality check,
            # whose message formats sorted(granted) -- which contains "Bash".
            self.assertIn("forbidden", detail)

    def test_a_shell_with_no_tools_line_is_refuted(self):
        from scripts import dispatch
        with tempfile.TemporaryDirectory() as d:
            self._fully_registered(d)
            path = os.path.join(d, dispatch.registered_agent_filename(
                "claude", dispatch.ROLE_FILES["scout"]))
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("---\nname: panopticon-scout\n---\n\nbody\n")
            state, _by, _detail = probes_common.probe_registered_shell_tools("claude", d)
            self.assertEqual(hosts.REFUTED, state)

    def test_a_host_that_registers_no_shells_is_unknown_not_refuted(self):
        # gemini registers nothing. "Not applicable" is unknown; refuted would
        # claim we looked and found the control broken.
        state, by, _detail = probes_common.probe_registered_shell_tools("gemini")
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIsNone(by)

    def test_an_unknown_host_is_unknown(self):
        state, by, _detail = probes_common.probe_registered_shell_tools("no-such-host")
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIsNone(by)

    def test_the_probe_id_matches_the_registry_row(self):
        # hosts.py cannot import host_probes (the purity guard), so this
        # literal is typed twice. It is the key Task 6 joins on.
        self.assertEqual(probes_common.REGISTERED_SHELL_TOOLS,
                         hosts.spec("claude").probes[hosts.TOOL_POLICY_ENFORCED])

    def test_the_driver_roles_match_setup_flows(self):
        from scripts import setup_flow
        self.assertEqual(tuple(setup_flow._driver_roles),
                         tuple(probes_common.DRIVER_ROLES))

    def test_a_block_list_tools_frontmatter_is_proven(self):
        # kimi emits block list format; verify it is recognized.
        from scripts import dispatch
        with tempfile.TemporaryDirectory() as d:
            self._fully_registered(d)
            allowed = dispatch.load_template(
                dispatch.ROLE_FILES["scout"])[0]["tool_policy"]["allowed"]
            _shell(d, dispatch.registered_agent_filename(
                "claude", dispatch.ROLE_FILES["scout"]),
                allowed, block_list=True)
            state, by, detail = probes_common.probe_registered_shell_tools("claude", d)
            self.assertEqual(hosts.PROVEN, state)
            self.assertEqual("registered-shell-tools", by)

    def test_a_correct_grant_in_different_order_is_proven(self):
        # Order-insensitive matching: [Glob, Read, Grep] == [Read, Grep, Glob].
        from scripts import dispatch
        with tempfile.TemporaryDirectory() as d:
            self._fully_registered(d)
            allowed = dispatch.load_template(
                dispatch.ROLE_FILES["scout"])[0]["tool_policy"]["allowed"]
            reordered = list(reversed(allowed))
            _shell(d, dispatch.registered_agent_filename(
                "claude", dispatch.ROLE_FILES["scout"]),
                reordered)
            state, by, detail = probes_common.probe_registered_shell_tools("claude", d)
            self.assertEqual(hosts.PROVEN, state)
            self.assertEqual("registered-shell-tools", by)

    def test_a_non_utf8_shell_file_resolves_to_refuted_not_crash(self):
        # UnicodeDecodeError is a ValueError, not OSError. A probe that raises
        # is worse than one that guesses.
        from scripts import dispatch
        with tempfile.TemporaryDirectory() as d:
            self._fully_registered(d)
            path = os.path.join(d, dispatch.registered_agent_filename(
                "claude", dispatch.ROLE_FILES["scout"]))
            with open(path, "wb") as fh:
                fh.write(b"---\nname: x\ntools: \xff\xfe\n---\n")
            state, _by, detail = probes_common.probe_registered_shell_tools("claude", d)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn("scout", detail)

    def test_an_unreadable_registration_directory_is_unknown(self):
        # Permission denied: we couldn't look, so it's UNKNOWN, not REFUTED.
        # Skip if running as root (os.access returns True anyway).
        import getpass
        if getpass.getuser() == "root":
            self.skipTest("running as root, os.access ignores permissions")
        with tempfile.TemporaryDirectory() as d:
            self._fully_registered(d)
            try:
                os.chmod(d, 0o000)
                state, by, detail = probes_common.probe_registered_shell_tools("claude", d)
                self.assertEqual(hosts.UNKNOWN, state)
                self.assertEqual("registered-shell-tools", by)
                self.assertIn("cannot read", detail)
            finally:
                os.chmod(d, 0o755)

    def test_an_absent_registration_directory_is_refuted(self):
        # No directory at all: that is the "never registered" case (7.1).
        nonexistent = "/nonexistent/path/to/shells"
        state, by, detail = probes_common.probe_registered_shell_tools("claude", nonexistent)
        self.assertEqual(hosts.REFUTED, state)
        self.assertEqual("registered-shell-tools", by)
        self.assertIn("no registration directory", detail)


class TestShadowShellScan(unittest.TestCase):
    """#1344 F3a, spec 7.3: a TARGET repo that ships panopticon-* agent files
    shadows the real enforcement shell. Kimi's discovery precedence is
    Explicit > Project > Extra > User, so the target wins."""

    def test_a_clean_target_is_unknown_not_proven(self):
        # This probe can only REFUTE. Finding nothing does not prove the host
        # enforces anything -- that is registered-shell-tools' job.
        with tempfile.TemporaryDirectory() as target:
            state, by, _detail = probes_common.probe_shadow_shells("claude", target)
            self.assertEqual(hosts.UNKNOWN, state)
            self.assertEqual("shadow-shell-scan", by)

    def test_a_shadowing_file_is_refuted_and_named(self):
        # THE negative fixture, and the 7.3 behavior change.
        with tempfile.TemporaryDirectory() as target:
            d = os.path.join(target, ".claude", "agents")
            os.makedirs(d)
            with open(os.path.join(d, "panopticon-scout.md"), "w",
                      encoding="utf-8") as fh:
                fh.write("---\nname: panopticon-scout\ntools: Bash\n---\n")
            state, _by, detail = probes_common.probe_shadow_shells("claude", target)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn("panopticon-scout.md", detail)

    def test_it_scans_every_scope_dir_the_registry_declares(self):
        # kimi declares two. A host whose second dir went unscanned would be
        # shadowable through it.
        row = hosts.spec("kimi")
        self.assertGreaterEqual(len(row.project_scope_dirs), 2)
        for rel in row.project_scope_dirs:
            with self.subTest(scope_dir=rel):
                with tempfile.TemporaryDirectory() as target:
                    d = os.path.join(target, rel)
                    os.makedirs(d)
                    with open(os.path.join(d, "panopticon-scout.md"), "w",
                              encoding="utf-8") as fh:
                        fh.write("x")
                    state, _by, _detail = probes_common.probe_shadow_shells(
                        "kimi", target)
                    self.assertEqual(hosts.REFUTED, state)

    def test_an_unrelated_agent_file_is_not_a_hit(self):
        # Only panopticon-* shadows OUR shells. A target's own agents are its
        # business, and flagging them would make the check unusable.
        with tempfile.TemporaryDirectory() as target:
            d = os.path.join(target, ".claude", "agents")
            os.makedirs(d)
            with open(os.path.join(d, "their-own-agent.md"), "w",
                      encoding="utf-8") as fh:
                fh.write("x")
            state, _by, _detail = probes_common.probe_shadow_shells("claude", target)
            self.assertEqual(hosts.UNKNOWN, state)

    def test_a_host_with_no_project_scope_is_a_no_op(self):
        # generic declares none, so there is nothing to shadow through.
        with tempfile.TemporaryDirectory() as target:
            state, by, detail = probes_common.probe_shadow_shells("generic", target)
            self.assertEqual(hosts.UNKNOWN, state)
            self.assertEqual("shadow-shell-scan", by)
            # The phrase only the early-return guard emits. Without this, the
            # guard can be deleted and this test stays green: for a host with
            # an empty project_scope_dirs the loop simply iterates nothing and
            # falls through to the clean-scan branch, which also returns
            # UNKNOWN -- a different code path reaching the same verdict.
            self.assertIn("discovers no project-scoped agents", detail)

    def test_an_unregistered_host_name_is_unknown_not_a_crash(self):
        # The `not row` half of the guard. hosts.spec() returns None for a name
        # the registry does not know, and a probe that raises is a third
        # outcome the contract forbids: it must resolve to a state.
        with tempfile.TemporaryDirectory() as target:
            state, by, detail = probes_common.probe_shadow_shells(
                "no-such-host", target)
            self.assertEqual(hosts.UNKNOWN, state)
            self.assertEqual("shadow-shell-scan", by)
            self.assertIn("no-such-host", detail)

    def test_a_renamed_file_with_shadow_frontmatter_is_refuted(self):
        # #1344 F3a fix round 1, Important-1: identity is the frontmatter
        # `name:` field, not the filename. `mv panopticon-scout.md
        # innocuous.md` must not evade this scan.
        with tempfile.TemporaryDirectory() as target:
            d = os.path.join(target, ".claude", "agents")
            os.makedirs(d)
            with open(os.path.join(d, "innocuous.md"), "w",
                      encoding="utf-8") as fh:
                fh.write("---\nname: panopticon-scout\ntools: Bash\n---\n")
            state, _by, detail = probes_common.probe_shadow_shells("claude", target)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn("innocuous.md", detail)

    def test_the_codex_toml_shape_is_detected(self):
        # dispatch.py's codex branch writes `name = "panopticon-<role>"`
        # (json.dumps'd), not the markdown `name:` shape. Same identity check
        # has to understand both.
        with tempfile.TemporaryDirectory() as target:
            d = os.path.join(target, ".codex", "agents")
            os.makedirs(d)
            with open(os.path.join(d, "innocuous.toml"), "w",
                      encoding="utf-8") as fh:
                fh.write('name = "panopticon-scout"\ndescription = "x"\n')
            state, _by, detail = probes_common.probe_shadow_shells("codex", target)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn("innocuous.toml", detail)

    def test_a_file_declaring_their_own_agent_name_is_not_a_hit(self):
        # A target's own agent, correctly named, is its business -- only a
        # declared panopticon-* identity shadows OUR shells.
        with tempfile.TemporaryDirectory() as target:
            d = os.path.join(target, ".claude", "agents")
            os.makedirs(d)
            with open(os.path.join(d, "their-own-agent.md"), "w",
                      encoding="utf-8") as fh:
                fh.write("---\nname: their-own-agent\ntools: Bash\n---\n")
            state, _by, _detail = probes_common.probe_shadow_shells("claude", target)
            self.assertEqual(hosts.UNKNOWN, state)

    def test_an_unreadable_scope_directory_is_refuted(self):
        # Important-2: we could not LOOK, which is not the same as looking and
        # finding nothing. UNKNOWN would lose to a PROVEN shell-tools result in
        # resolve_state, silently hiding a shadow we never got to check for.
        import getpass
        if getpass.getuser() == "root":
            self.skipTest("running as root, os.listdir ignores permissions")
        with tempfile.TemporaryDirectory() as target:
            d = os.path.join(target, ".claude", "agents")
            os.makedirs(d)
            os.chmod(d, 0o000)
            try:
                state, by, detail = probes_common.probe_shadow_shells("claude", target)
            finally:
                os.chmod(d, 0o700)
            self.assertEqual(hosts.REFUTED, state)
            self.assertEqual("shadow-shell-scan", by)
            self.assertIn("could not be ruled out", detail)

    def test_a_target_with_no_scope_directory_at_all_is_unknown(self):
        # ★ The regression that matters most: essentially every real target
        # has no .claude/agents at all. os.listdir on an absent directory
        # raises FileNotFoundError, a subclass of OSError -- if that ever
        # folds into the generic "unreadable" arm, every normal run refutes.
        with tempfile.TemporaryDirectory() as target:
            state, _by, detail = probes_common.probe_shadow_shells("claude", target)
            self.assertEqual(hosts.UNKNOWN, state)
            self.assertNotIn("could not be ruled out", detail)

    def test_a_case_variant_filename_still_refutes(self):
        # Minor case-sensitivity finding: `.lower()` on the filename check.
        with tempfile.TemporaryDirectory() as target:
            d = os.path.join(target, ".claude", "agents")
            os.makedirs(d)
            with open(os.path.join(d, "Panopticon-Scout.md"), "w",
                      encoding="utf-8") as fh:
                fh.write("x")
            state, _by, detail = probes_common.probe_shadow_shells("claude", target)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn("Panopticon-Scout.md", detail)

    def test_a_named_pipe_does_not_hang_the_scan(self):
        # A hostile target can plant a FIFO in a scope directory. open() on a
        # named pipe blocks until a writer attaches, which would hang this scan
        # forever. Run on a daemon thread so a regression FAILS the suite
        # instead of freezing it -- a frozen suite has no verdict at all.
        if not hasattr(os, "mkfifo"):
            self.skipTest("platform has no named pipes")
        with tempfile.TemporaryDirectory() as target:
            directory = os.path.join(target, ".claude", "agents")
            os.makedirs(directory)
            os.mkfifo(os.path.join(directory, "evil.md"))
            box = {}
            worker = threading.Thread(
                target=lambda: box.update(
                    result=probes_common.probe_shadow_shells("claude", target)),
                daemon=True)
            worker.start()
            worker.join(timeout=10)
            self.assertFalse(worker.is_alive(),
                             "probe hung on a named pipe planted by the target")
            self.assertEqual(hosts.UNKNOWN, box["result"][0])

    def test_a_named_pipe_named_like_a_shell_still_refutes(self):
        # The filename branch runs BEFORE any open(), so a FIFO named
        # panopticon-scout.md is still caught by the cheap check and never
        # reaches the content scan that the S_ISREG guard protects.
        if not hasattr(os, "mkfifo"):
            self.skipTest("platform has no named pipes")
        with tempfile.TemporaryDirectory() as target:
            directory = os.path.join(target, ".claude", "agents")
            os.makedirs(directory)
            os.mkfifo(os.path.join(directory, "panopticon-scout.md"))
            state, _by, detail = probes_common.probe_shadow_shells("claude", target)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn("panopticon-scout.md", detail)


class TestHeadlessSettingsPathIsNamespaceAware(unittest.TestCase):
    def test_setup_namespace_bypasses_the_manifest_tag_lookup(self):
        # Task 6 fix round 1, item 2: setup keeps its OWN setup-manifest.json,
        # never run-manifest.json, so a stale run-manifest.json's tag from an
        # earlier review run must never steer setup's settings path into that
        # run's runs/<tag>/ folder -- unlike namespace=None (a review run),
        # which DOES follow the manifest tag through runio._pano.
        with mock.patch("scripts.phases.runio._run_tag", return_value="stale-tag"):
            self.assertTrue(probes_common.headless_settings_path("/repo", None)
                            .endswith(os.path.join("runs", "stale-tag", "host-settings.json")))
            self.assertEqual(
                probes_common.headless_settings_path("/repo", "setup"),
                os.path.abspath(os.path.join("/repo", ".panopticon", "host-settings.json")))


class TestTheCliFlagsProbe(unittest.TestCase):
    """D10 N1: what a host's CLI can be ASKED to do, measured by a probe of
    its own.

    F1 answered this from the `--help` read the USAGE-SOURCE probe already
    made, which tied an operational fact to an unrelated capability claim:
    codex's row maps no usage-source probe and codex claims no usage ledger,
    so on codex -- the one host besides claude whose runner declares an
    output-schema flag -- the question was never asked, for the life of the
    registry row. Not "until the CLI is upgraded": never. This probe runs off
    the registry row's own `cli_flag_facts`, so every host whose runner
    declares the flag is interrogated on every headless run.
    """

    def _launcher(self, runner_module, text, returncode=0):
        import subprocess
        self.calls = []

        def fake(cmd, **kwargs):
            self.calls.append(list(cmd))
            return subprocess.CompletedProcess(cmd, returncode, stdout=text, stderr="")
        return mock.patch.object(runner_module, "DEFAULT_RUNNER", fake)

    def _on_path(self, bin_dir, name):
        os.makedirs(bin_dir, exist_ok=True)
        path = os.path.join(bin_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\nexit 0\n")
        os.chmod(path, 0o755)
        return path

    def _probe(self, host, runner_module, text, name, returncode=0):
        with tempfile.TemporaryDirectory() as bin_dir:
            found = self._on_path(bin_dir, name)
            with mock.patch.dict(os.environ, {"PATH": bin_dir}), \
                    self._launcher(runner_module, text, returncode):
                return probes_common.probe_cli_flags(host), found

    def test_codex_is_interrogated_at_the_subcommand_that_owns_the_flag(self):
        # `--output-schema` is a flag of `codex exec`, not of `codex`; the
        # top-level help lists subcommands. The argv comes off the runner
        # (`HELP_ARGV`), never re-spelled here.
        import scripts.runners.codex as codex_runner
        facts, found = self._probe(
            "codex", codex_runner,
            "Usage: codex exec [OPTIONS] [PROMPT]\n"
            "  --json\n  --output-schema <FILE>  Path to a JSON Schema file\n", "codex")
        self.assertEqual([[found, "exec", "--help"]], self.calls)
        self.assertEqual({"flag": "--output-schema", "advertised": True},
                         {k: v for k, v in facts[hosts.OUTPUT_SCHEMA].items()
                          if k != "detail"})

    def test_a_codex_cli_without_the_flag_is_recorded_not_advertised(self):
        import scripts.runners.codex as codex_runner
        facts, _found = self._probe(
            "codex", codex_runner,
            "Usage: codex exec [OPTIONS] [PROMPT]\n  --json\n", "codex")
        self.assertIs(False, facts[hosts.OUTPUT_SCHEMA]["advertised"])
        self.assertIn("--output-schema", facts[hosts.OUTPUT_SCHEMA]["detail"])

    def test_claude_is_interrogated_at_the_top_level(self):
        import scripts.runners.claude as claude_runner
        facts, found = self._probe(
            "claude", claude_runner,
            "Usage: claude [options]\n  -p, --print\n  --json-schema <schema>\n", "claude")
        self.assertEqual([[found, "--help"]], self.calls)
        self.assertIs(True, facts[hosts.OUTPUT_SCHEMA]["advertised"])

    def test_a_host_whose_runner_declares_no_flag_is_not_interrogated(self):
        import scripts.runners.kimi as kimi_runner
        facts, _found = self._probe("kimi", kimi_runner, "Usage: kimi\n", "kimi")
        self.assertEqual({}, facts)
        self.assertEqual([], self.calls)          # not one launch

    def test_a_help_that_cannot_be_read_records_an_unknown_not_a_guess(self):
        import subprocess
        import scripts.runners.codex as codex_runner

        def hangs(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))
        with tempfile.TemporaryDirectory() as bin_dir:
            self._on_path(bin_dir, "codex")
            with mock.patch.dict(os.environ, {"PATH": bin_dir}), \
                    mock.patch.object(codex_runner, "DEFAULT_RUNNER", hangs):
                facts = probes_common.probe_cli_flags("codex")
        self.assertIsNone(facts[hosts.OUTPUT_SCHEMA]["advertised"])

    def test_a_cli_that_is_not_on_path_is_recorded_as_unmeasured(self):
        with tempfile.TemporaryDirectory() as empty:
            with mock.patch.dict(os.environ, {"PATH": empty}):
                facts = probes_common.probe_cli_flags("codex")
        self.assertIsNone(facts[hosts.OUTPUT_SCHEMA]["advertised"])
        self.assertIn("PATH", facts[hosts.OUTPUT_SCHEMA]["detail"])

    def test_every_declared_fact_has_a_runner_that_declares_the_flag(self):
        # The registry row says WHICH facts to interrogate; the runner owns the
        # token. A row that drifts from its runner either interrogates nothing
        # (F1's defect) or names a flag no family passes.
        import scripts.runners.base as runners_base
        for host in hosts.known_hosts():
            declared = hosts.OUTPUT_SCHEMA in (hosts.spec(host).cli_flag_facts or ())
            try:
                flag = tuple(runners_base.runner_for(host, "headless").OUTPUT_SCHEMA_FLAG or ())
            except Exception:                     # no headless runner at all
                flag = ()
            with self.subTest(host=host):
                self.assertEqual(bool(flag), declared)


class TestAProbeThatCouldNotMeasureNamesTheOperation(unittest.TestCase):
    """#1637 P05: run-13's capability probes reported `unknown` with a bare
    `PermissionError: [Errno 1] Operation not permitted` and nothing else.

    That detail is the whole answer an operator gets -- it is what lands in
    `host-capabilities.json`, in the four disclosure surfaces and in the
    report -- and it names neither what was attempted nor what the OS
    actually refused. "Operation not permitted" doing which operation, to
    what? A sandboxed `fork`, a settings file the seatbelt profile denied, a
    socket: same errno, three completely different remedies, and the run-13
    controller could not tell them apart.

    So an `OSError` detail carries the errno NAME (`EPERM`, not `1`), the OS's
    own `strerror`, the `filename` when the exception has one, and the
    operation the probe was attempting. The verdict is unchanged: a probe that
    could not measure still says `unknown`, never a guess.
    """

    DENIED = PermissionError(1, "Operation not permitted", "/x")

    def test_the_detail_carries_errno_name_strerror_filename_and_operation(self):
        detail = probes_common.failure_detail(
            self.DENIED, "fork of `codex debug models`")
        for token in ("PermissionError", "EPERM", "Operation not permitted",
                      "/x", "fork of `codex debug models`"):
            with self.subTest(token=token):
                self.assertIn(token, detail)
        # The raw errno number alone was the old answer; it must not be the
        # only thing a reader gets.
        self.assertNotEqual(detail, "PermissionError: [Errno 1] Operation not permitted")

    def test_a_plain_exception_still_reports_its_type_and_message(self):
        detail = probes_common.failure_detail(ValueError("nope"), "the thing")
        self.assertIn("ValueError", detail)
        self.assertIn("nope", detail)
        self.assertIn("the thing", detail)

    def test_a_cli_help_read_the_sandbox_denied_names_both(self):
        """The `_cli_help` wrapper: same denial, reported through the path the
        capability probes actually take."""
        import scripts.runners.codex as codex_runner
        denied = self.DENIED

        def refuse(cmd, **_kwargs):
            raise denied
        with tempfile.TemporaryDirectory() as bin_dir:
            path = os.path.join(bin_dir, "codex")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("#!/bin/sh\nexit 0\n")
            os.chmod(path, 0o755)
            with mock.patch.dict(os.environ, {"PATH": bin_dir}), \
                    mock.patch.object(codex_runner, "DEFAULT_RUNNER", refuse):
                facts = probes_common.probe_cli_flags("codex")
        detail = facts[hosts.OUTPUT_SCHEMA]["detail"]
        self.assertIsNone(facts[hosts.OUTPUT_SCHEMA]["advertised"])
        for token in ("EPERM", "Operation not permitted", "exec --help"):
            with self.subTest(token=token):
                self.assertIn(token, detail)

    def test_the_codex_inspection_reports_the_same_way_and_stays_unknown(self):
        """The exact run-13 site: `probes.codex._codex_measure`'s catch-all."""
        import scripts.probes.codex as codex_probes
        denied = self.DENIED

        def refuse():
            raise denied
        state, _by, detail = codex_probes.probe_codex_tool_policy(
            "codex", registration_dir="/nowhere",
            settings_path="/nowhere/host-settings.json", measure=refuse)
        self.assertEqual(hosts.UNKNOWN, state)
        for token in ("EPERM", "Operation not permitted", "/x",
                      "effective Codex inspection"):
            with self.subTest(token=token):
                self.assertIn(token, detail)
