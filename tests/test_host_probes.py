import os
import tempfile
import unittest

from scripts import host_probes, hosts


def _shell(directory, name, tools, block_list=False):
    """Write a registered shell with the given `tools:` line (inline or block list).

    If block_list=True, emits YAML block format: tools:\n  - Read\n  - Grep
    Otherwise, emits inline format: tools: Read, Grep
    """
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, name)
    if block_list:
        block_items = "\n".join("  - %s" % t for t in tools)
        content = ("---\nname: %s\ndescription: probe fixture\ntools:\n%s\n"
                   "---\n\nbody\n" % (name[:-3], block_items))
    else:
        content = ("---\nname: %s\ndescription: probe fixture\ntools: %s\n"
                   "---\n\nbody\n" % (name[:-3], ", ".join(tools)))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


class TestRegisteredShellToolsProbe(unittest.TestCase):
    """#1344 F3a: proves the host really registered the shells it claims."""

    def _fully_registered(self, directory):
        from scripts import dispatch
        for role in host_probes.DRIVER_ROLES:
            role_file = dispatch.ROLE_FILES[role]
            allowed = dispatch.load_template(role_file)[0]["tool_policy"]["allowed"]
            _shell(directory, dispatch.registered_agent_filename("claude", role_file),
                   allowed)

    def test_a_complete_correct_registration_is_proven(self):
        with tempfile.TemporaryDirectory() as d:
            self._fully_registered(d)
            state, by, detail = host_probes.probe_registered_shell_tools("claude", d)
            self.assertEqual(hosts.PROVEN, state)
            self.assertEqual("registered-shell-tools", by)
            self.assertIn("3/3", detail)

    def test_an_empty_registration_dir_is_refuted(self):
        # THE negative fixture. This is the 7.1 case: a Claude run whose
        # shells were never registered must stop claiming enforcement.
        with tempfile.TemporaryDirectory() as d:
            state, _by, detail = host_probes.probe_registered_shell_tools("claude", d)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn("scout", detail)

    def test_one_missing_role_is_refuted_and_named(self):
        from scripts import dispatch
        with tempfile.TemporaryDirectory() as d:
            self._fully_registered(d)
            os.remove(os.path.join(d, dispatch.registered_agent_filename(
                "claude", dispatch.ROLE_FILES["domain_panel"])))
            state, _by, detail = host_probes.probe_registered_shell_tools("claude", d)
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
            state, _by, detail = host_probes.probe_registered_shell_tools("claude", d)
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
            state, _by, _detail = host_probes.probe_registered_shell_tools("claude", d)
            self.assertEqual(hosts.REFUTED, state)

    def test_a_host_that_registers_no_shells_is_unknown_not_refuted(self):
        # gemini registers nothing. "Not applicable" is unknown; refuted would
        # claim we looked and found the control broken.
        state, by, _detail = host_probes.probe_registered_shell_tools("gemini")
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIsNone(by)

    def test_an_unknown_host_is_unknown(self):
        state, by, _detail = host_probes.probe_registered_shell_tools("no-such-host")
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIsNone(by)

    def test_the_probe_id_matches_the_registry_row(self):
        # hosts.py cannot import host_probes (the purity guard), so this
        # literal is typed twice. It is the key Task 6 joins on.
        self.assertEqual(host_probes.REGISTERED_SHELL_TOOLS,
                         hosts.spec("claude").probes[hosts.TOOL_POLICY_ENFORCED])

    def test_the_driver_roles_match_setup_flows(self):
        from scripts import setup_flow
        self.assertEqual(tuple(setup_flow._driver_roles),
                         tuple(host_probes.DRIVER_ROLES))

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
            state, by, detail = host_probes.probe_registered_shell_tools("claude", d)
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
            state, by, detail = host_probes.probe_registered_shell_tools("claude", d)
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
            state, _by, detail = host_probes.probe_registered_shell_tools("claude", d)
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
                state, by, detail = host_probes.probe_registered_shell_tools("claude", d)
                self.assertEqual(hosts.UNKNOWN, state)
                self.assertEqual("registered-shell-tools", by)
                self.assertIn("cannot read", detail)
            finally:
                os.chmod(d, 0o755)

    def test_an_absent_registration_directory_is_refuted(self):
        # No directory at all: that is the "never registered" case (7.1).
        nonexistent = "/nonexistent/path/to/shells"
        state, by, detail = host_probes.probe_registered_shell_tools("claude", nonexistent)
        self.assertEqual(hosts.REFUTED, state)
        self.assertEqual("registered-shell-tools", by)
        self.assertIn("no registration directory", detail)


class TestWriteGuardArmedProbe(unittest.TestCase):
    """#1344 F3a: proves the host CAN mediate Write, not that it is doing so
    right now -- the guard is armed by the host during fan-out, so at run
    start it is legitimately not registered."""

    def _session_root(self, root):
        """A session root shaped the way write_guard_hook.install() demands.

        install() refuses to arm when the settings file does not already exist
        (#1493): a missing one means the caller is in the wrong directory and
        the guard would never be consulted. The probe must apply the same rule,
        so the fixture must satisfy it.
        """
        claude = os.path.join(root, ".claude")
        os.makedirs(claude, exist_ok=True)
        with open(os.path.join(claude, "settings.local.json"), "w",
                  encoding="utf-8") as fh:
            fh.write("{}")
        return claude

    def test_a_working_guard_and_a_writable_settings_root_is_proven(self):
        with tempfile.TemporaryDirectory() as session_root:
            self._session_root(session_root)
            state, by, detail = host_probes.probe_write_guard_armed(
                "claude", session_root=session_root)
            self.assertEqual(hosts.PROVEN, state)
            self.assertEqual("write-guard-armed", by)
            self.assertIn(session_root, detail)   # #1493: name the resolved path

    def test_it_does_not_require_the_guard_to_be_armed_right_now(self):
        # THE regression this probe exists to avoid. A prototype that gated on
        # live arming returned REFUTED on a correctly configured machine,
        # which would have made require_unenforced_ack refuse every Claude run.
        from scripts import write_guard_hook
        with tempfile.TemporaryDirectory() as session_root:
            self._session_root(session_root)
            live = write_guard_hook.guard_state(session_root=session_root)
            self.assertFalse(live["armed"], "fixture precondition: not armed")
            state, _by, _detail = host_probes.probe_write_guard_armed(
                "claude", session_root=session_root)
            self.assertEqual(hosts.PROVEN, state)

    def test_a_missing_settings_file_is_refuted(self):
        # THE #1493 fixture. install() REFUSES to arm when the settings file
        # does not already exist, because a missing one means the caller is in
        # the wrong directory and the guard would arm where nothing reads it.
        # A probe that proved the capability here would prove something
        # install() will then refuse to do.
        with tempfile.TemporaryDirectory() as session_root:
            os.makedirs(os.path.join(session_root, ".claude"), exist_ok=True)
            state, _by, detail = host_probes.probe_write_guard_armed(
                "claude", session_root=session_root)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn("settings.local.json", detail)

    def test_an_unwritable_settings_root_is_refuted(self):
        # THE negative fixture: the host cannot arm what it cannot write.
        with tempfile.TemporaryDirectory() as session_root:
            claude_dir = self._session_root(session_root)
            os.chmod(claude_dir, 0o500)          # r-x: no writes
            try:
                state, _by, detail = host_probes.probe_write_guard_armed(
                    "claude", session_root=session_root)
            finally:
                os.chmod(claude_dir, 0o700)      # restore so cleanup succeeds
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn(claude_dir, detail)

    def test_a_host_that_claims_no_write_guard_is_unknown(self):
        for name in ("gemini", "generic"):
            with self.subTest(host=name):
                state, by, _detail = host_probes.probe_write_guard_armed(name)
                self.assertEqual(hosts.UNKNOWN, state)
                self.assertIsNone(by)

    def test_the_probe_leaves_live_settings_untouched(self):
        # The probe must never write to the operator's real session settings.
        from scripts import write_guard_hook
        before = write_guard_hook.guard_state()
        host_probes.probe_write_guard_armed("claude")
        self.assertEqual(before, write_guard_hook.guard_state())


class TestTranscriptDirProbe(unittest.TestCase):
    """#1344 F3a: usage_ledger is operational, not security (8.1 excludes it
    from F5's bar), but an unprobed capability must still say so."""

    def _transcripts(self, home, project_dir):
        from scripts import collect_usage
        d = os.path.join(home, ".claude", "projects",
                         collect_usage.project_slug(project_dir))
        os.makedirs(d, exist_ok=True)
        return d

    def test_a_readable_transcript_dir_is_proven(self):
        with tempfile.TemporaryDirectory() as home, \
                tempfile.TemporaryDirectory() as project:
            d = self._transcripts(home, project)
            state, by, detail = host_probes.probe_transcript_dir(
                "claude", project, home=home)
            self.assertEqual(hosts.PROVEN, state)
            self.assertEqual("transcript-dir", by)
            self.assertIn(d, detail)

    def test_an_absent_transcript_dir_is_refuted(self):
        # THE negative fixture. A host that claims a usage ledger and has no
        # transcripts cannot produce one.
        with tempfile.TemporaryDirectory() as home, \
                tempfile.TemporaryDirectory() as project:
            state, _by, detail = host_probes.probe_transcript_dir(
                "claude", project, home=home)
            self.assertEqual(hosts.REFUTED, state)
            self.assertEqual("transcript-dir", _by)
            # The phrase only the isdir branch emits. Asserting on ".claude"
            # instead passes either way: the not-readable branch formats the
            # same `directory` string, and os.access() on a nonexistent path
            # also returns False, so deleting the isdir branch would leave this
            # test green while the message became factually wrong.
            self.assertIn("no transcript directory", detail)

    def test_an_unreadable_transcript_dir_is_refuted(self):
        # Skip if running as root (os.access returns True anyway).
        import getpass
        if getpass.getuser() == "root":
            self.skipTest("running as root, os.access ignores permissions")
        with tempfile.TemporaryDirectory() as home, \
                tempfile.TemporaryDirectory() as project:
            d = self._transcripts(home, project)
            os.chmod(d, 0o000)
            try:
                state, by, detail = host_probes.probe_transcript_dir(
                    "claude", project, home=home)
            finally:
                os.chmod(d, 0o700)
            self.assertEqual(hosts.REFUTED, state)
            self.assertEqual("transcript-dir", by)
            self.assertIn(d, detail)

    def test_a_host_that_claims_no_usage_ledger_is_unknown(self):
        for name in ("gemini", "generic", "codex"):
            with self.subTest(host=name):
                state, by, _detail = host_probes.probe_transcript_dir(name, ".")
                self.assertEqual(hosts.UNKNOWN, state)
                self.assertIsNone(by)

    def test_the_transcript_probe_id_matches_the_registry_row(self):
        self.assertEqual(host_probes.TRANSCRIPT_DIR,
                         hosts.spec("claude").probes[hosts.USAGE_LEDGER])


class TestShadowShellScan(unittest.TestCase):
    """#1344 F3a, spec 7.3: a TARGET repo that ships panopticon-* agent files
    shadows the real enforcement shell. Kimi's discovery precedence is
    Explicit > Project > Extra > User, so the target wins."""

    def test_a_clean_target_is_unknown_not_proven(self):
        # This probe can only REFUTE. Finding nothing does not prove the host
        # enforces anything -- that is registered-shell-tools' job.
        with tempfile.TemporaryDirectory() as target:
            state, by, _detail = host_probes.probe_shadow_shells("claude", target)
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
            state, _by, detail = host_probes.probe_shadow_shells("claude", target)
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
                    state, _by, _detail = host_probes.probe_shadow_shells(
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
            state, _by, _detail = host_probes.probe_shadow_shells("claude", target)
            self.assertEqual(hosts.UNKNOWN, state)

    def test_a_host_with_no_project_scope_is_a_no_op(self):
        # generic declares none, so there is nothing to shadow through.
        with tempfile.TemporaryDirectory() as target:
            state, _by, _detail = host_probes.probe_shadow_shells("generic", target)
            self.assertEqual(hosts.UNKNOWN, state)
