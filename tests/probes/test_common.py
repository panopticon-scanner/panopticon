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
