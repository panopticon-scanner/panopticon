import contextlib
import os
import tempfile
import threading
import unittest
from unittest import mock

from scripts import host_probes, hosts, write_guard_hook


@contextlib.contextmanager
def _in(path):
    """Run the block with `path` as the process cwd, always restoring it.

    The write-guard probe's DEFAULT subject is cwd-relative (that is what
    `write_guard_hook._resolve(None, None, None)` returns), so pinning it
    means controlling cwd -- and controlling cwd is also what keeps these
    tests off the operator's real `.claude/settings.local.json`.
    """
    previous = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


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

    def test_the_probe_leaves_the_sessions_settings_untouched(self):
        # The probe must never write to the session's settings: it proves the
        # MECHANISM in a sandbox, and merely LOOKS at the place the host will
        # arm. Minor 2: this test used to call the probe with no session_root,
        # which resolves `.claude/settings.local.json` CWD-relative -- a file
        # that is untracked in this repo, so on a fresh checkout or CI runner
        # the probe short-circuited at the `isfile` check and the round-trip
        # this test exists to guard never ran. It passed, hollowly, exactly
        # where it mattered. Asserting PROVEN makes the precondition
        # load-bearing, and a temp session root guarantees it rather than
        # inheriting it from the checkout.
        with tempfile.TemporaryDirectory() as session_root:
            self._session_root(session_root)
            before = write_guard_hook.guard_state(session_root=session_root)
            state, _by, _detail = host_probes.probe_write_guard_armed(
                "claude", session_root=session_root)
            self.assertEqual(hosts.PROVEN, state)
            self.assertEqual(
                before, write_guard_hook.guard_state(session_root=session_root))

    def test_the_probe_and_install_resolve_the_same_settings_file(self):
        # I1: the probe's SUBJECT must be the file `install()` will arm. The
        # coupling is `write_guard_hook._resolve`, called by both; re-deriving
        # the path here would be a second definition free to drift, and a
        # probe that proves a file nothing arms proves nothing. Pinned by
        # REMOVING exactly the file _resolve names and watching the verdict
        # flip -- a detail-string match alone would not show the probe reads
        # that file rather than some other one with the same name.
        with tempfile.TemporaryDirectory() as session_root:
            self._session_root(session_root)
            resolved, _allowlist, _defaults = write_guard_hook._resolve(
                None, None, session_root)
            state, _by, detail = host_probes.probe_write_guard_armed(
                "claude", session_root=session_root)
            self.assertEqual(hosts.PROVEN, state)
            self.assertIn(resolved, detail)
            os.remove(resolved)
            state, _by, detail = host_probes.probe_write_guard_armed(
                "claude", session_root=session_root)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn(os.path.abspath(resolved), detail)

    def test_the_default_subject_is_the_file_install_resolves_from_cwd(self):
        # The other half of I1: no session_root at all. install()'s default is
        # CWD-relative, so the probe's must be too -- and this runs entirely
        # inside a temp cwd, which is also why it never reads the operator's
        # real settings file.
        with tempfile.TemporaryDirectory() as cwd, _in(cwd):
            resolved, _allowlist, used_defaults = write_guard_hook._resolve(
                None, None, None)
            self.assertTrue(used_defaults)
            self.assertFalse(os.path.isabs(resolved))   # cwd-relative by design
            state, _by, detail = host_probes.probe_write_guard_armed("claude")
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn(os.path.abspath(resolved), detail)
            os.makedirs(os.path.dirname(resolved), exist_ok=True)
            with open(resolved, "w", encoding="utf-8") as fh:
                fh.write("{}")
            state, _by, _detail = host_probes.probe_write_guard_armed("claude")
            self.assertEqual(hosts.PROVEN, state)

    def test_defaulting_the_session_root_to_cwd_does_not_move_the_subject(self):
        # `run_probes` now always passes a session_root, defaulting it to cwd.
        # That is only safe because _resolve(None, None, os.getcwd()) and
        # _resolve(None, None, None) name the SAME file -- one absolute, one
        # cwd-relative. Measured here rather than assumed: the two differ in
        # `used_defaults`, which is what makes it worth checking.
        with tempfile.TemporaryDirectory() as cwd, _in(cwd):
            self._session_root(cwd)
            default = write_guard_hook._resolve(None, None, None)
            explicit = write_guard_hook._resolve(None, None, os.getcwd())
            self.assertEqual(os.path.abspath(default[0]),
                             os.path.abspath(explicit[0]))
            self.assertEqual(os.path.abspath(default[1]),
                             os.path.abspath(explicit[1]))
            self.assertNotEqual(default[2], explicit[2])   # used_defaults does differ
            self.assertEqual(
                host_probes.probe_write_guard_armed("claude")[0],
                host_probes.probe_write_guard_armed(
                    "claude", session_root=os.getcwd())[0])

    def test_a_sandbox_that_cannot_be_created_refutes_rather_than_raising(self):
        # Minor 6: the round-trip's try/except did not wrap
        # TemporaryDirectory() itself. This runs inside driver.run() on EVERY
        # invocation now, so an OSError from the constructor (no space, TMPDIR
        # gone, out of descriptors) aborted the whole run with a traceback --
        # violating this module's contract that a probe which cannot run
        # resolves to a STATE.
        with tempfile.TemporaryDirectory() as session_root:
            self._session_root(session_root)
            with mock.patch.object(host_probes.tempfile, "TemporaryDirectory",
                                   side_effect=OSError("no space left")):
                state, by, detail = host_probes.probe_write_guard_armed(
                    "claude", session_root=session_root)
        self.assertEqual(hosts.REFUTED, state)
        self.assertEqual(host_probes.WRITE_GUARD_ARMED, by)
        self.assertIn("no space left", detail)


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
            state, by, detail = host_probes.probe_shadow_shells("generic", target)
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
            state, by, detail = host_probes.probe_shadow_shells(
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
            state, _by, detail = host_probes.probe_shadow_shells("claude", target)
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
            state, _by, detail = host_probes.probe_shadow_shells("codex", target)
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
            state, _by, _detail = host_probes.probe_shadow_shells("claude", target)
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
                state, by, detail = host_probes.probe_shadow_shells("claude", target)
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
            state, _by, detail = host_probes.probe_shadow_shells("claude", target)
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
            state, _by, detail = host_probes.probe_shadow_shells("claude", target)
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
                    result=host_probes.probe_shadow_shells("claude", target)),
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
            state, _by, detail = host_probes.probe_shadow_shells("claude", target)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn("panopticon-scout.md", detail)


class TestRunProbesBuildsTheArtifact(unittest.TestCase):

    def test_every_capability_gets_a_row_even_unprobed_ones(self):
        # 5.1: "nobody looked" is written down, never inferred from an absent
        # key. read_scope_confined and model_binding have no probe in F3a.
        with tempfile.TemporaryDirectory() as target:
            art = host_probes.run_probes("claude", target)
            self.assertEqual(sorted(hosts.CAPABILITIES),
                             sorted(art["capabilities"]))
            for capability in hosts.CAPABILITIES:
                with self.subTest(capability=capability):
                    row = art["capabilities"][capability]
                    self.assertIn(row["state"], hosts.STATES)
                    self.assertTrue(row["detail"])

    def test_the_two_unprobed_capabilities_say_why(self):
        with tempfile.TemporaryDirectory() as target:
            art = host_probes.run_probes("claude", target)
            for capability in (hosts.READ_SCOPE_CONFINED, hosts.MODEL_BINDING):
                with self.subTest(capability=capability):
                    row = art["capabilities"][capability]
                    self.assertEqual(hosts.UNKNOWN, row["state"])
                    self.assertIsNone(row["by"])
                    self.assertIn("no probe", row["detail"])

    def test_an_unclaimed_capability_is_not_described_as_claimed(self):
        # Minor 1. One sentence covered both no-probe cases and said the host
        # "claims this capability's proof is not shipped yet". gemini claims
        # NOTHING, so its artifact asserted a claim it never made -- for two
        # capabilities -- in the one artifact whose entire purpose is
        # separating claims from proof.
        with tempfile.TemporaryDirectory() as target:
            art = host_probes.run_probes("gemini", target)
            unclaimed = [c for c in (hosts.ARTIFACT_WRITE_GUARD,
                                     hosts.USAGE_LEDGER)
                         if not hosts.declares("gemini", c)]
            self.assertEqual(2, len(unclaimed))   # the fixture is the real row
            for capability in unclaimed:
                with self.subTest(capability=capability):
                    detail = art["capabilities"][capability]["detail"]
                    self.assertIn("no probe", detail)
                    self.assertNotIn("claims", detail)
                    self.assertIn("does not claim", detail)

    def test_a_claimed_capability_with_no_probe_still_says_so(self):
        # The other side of the split, and what makes the assertion above
        # non-vacuous: a message that dropped the word "claims" everywhere
        # would pass that test while losing the distinction it exists to draw.
        # A host that DOES claim a capability but ships no probe for it is
        # waiting on the probe, and the artifact has to say that.
        from unittest import mock as _mock
        row = hosts.HostSpec(name="claims-but-unprobed",
                             claims=frozenset({hosts.ARTIFACT_WRITE_GUARD}))
        with _mock.patch.dict(hosts.HOSTS, {"claims-but-unprobed": row}), \
                tempfile.TemporaryDirectory() as target:
            art = host_probes.run_probes("claims-but-unprobed", target)
            detail = art["capabilities"][hosts.ARTIFACT_WRITE_GUARD]["detail"]
            self.assertIn("claims", detail)
            self.assertIn("not shipped yet", detail)

    def test_a_shadowed_target_refutes_tool_policy_even_when_shells_are_perfect(self):
        # The precedence rule, end to end: registered-shell-tools may prove it,
        # shadow-shell-scan refutes it, and refuted wins.
        from scripts import dispatch
        with tempfile.TemporaryDirectory() as target, \
                tempfile.TemporaryDirectory() as registration:
            for role in host_probes.DRIVER_ROLES:
                role_file = dispatch.ROLE_FILES[role]
                allowed = dispatch.load_template(role_file)[0]["tool_policy"]["allowed"]
                _shell(registration,
                       dispatch.registered_agent_filename("claude", role_file),
                       allowed)
            shadow = os.path.join(target, ".claude", "agents")
            os.makedirs(shadow)
            with open(os.path.join(shadow, "panopticon-scout.md"), "w",
                      encoding="utf-8") as fh:
                fh.write("x")
            art = host_probes.run_probes("claude", target,
                                         registration_dir=registration)
            row = art["capabilities"][hosts.TOOL_POLICY_ENFORCED]
            self.assertEqual(hosts.REFUTED, row["state"])
            self.assertEqual(host_probes.SHADOW_SHELL_SCAN, row["by"])
            self.assertIn("panopticon-scout.md", row["detail"])

    def test_the_schema_is_stamped_and_the_host_recorded(self):
        with tempfile.TemporaryDirectory() as target:
            art = host_probes.run_probes("claude", target)
            self.assertEqual(1, art["schema_version"])
            self.assertEqual("claude", art["host"])
            self.assertTrue(art["probed_at"])

    def test_capabilities_of_ignores_the_timestamp(self):
        # The comparison on resume must not fire merely because time passed.
        with tempfile.TemporaryDirectory() as target:
            first = host_probes.run_probes("claude", target)
            second = dict(first, probed_at="1999-01-01T00:00:00Z")
            self.assertEqual(host_probes.capabilities_of(first),
                             host_probes.capabilities_of(second))

    def test_a_host_the_registry_does_not_know_probes_to_all_unknown(self):
        with tempfile.TemporaryDirectory() as target:
            art = host_probes.run_probes("no-such-host", target)
            self.assertEqual({hosts.UNKNOWN},
                             {r["state"] for r in art["capabilities"].values()})
            # `state` alone cannot tell "nothing probed this" from "a probe
            # ran and landed on unknown" -- assert `by` too. The shadow scan
            # runs for every host, even one the registry has never heard of,
            # and reports that it had nowhere to look; nothing else runs.
            self.assertEqual(
                host_probes.SHADOW_SHELL_SCAN,
                art["capabilities"][hosts.TOOL_POLICY_ENFORCED]["by"])
            for capability in hosts.CAPABILITIES:
                if capability == hosts.TOOL_POLICY_ENFORCED:
                    continue
                with self.subTest(capability=capability):
                    self.assertIsNone(art["capabilities"][capability]["by"])

    def test_a_known_host_that_claims_nothing_probes_to_all_unknown(self):
        # Distinct from the unknown-host-NAME case above: "gemini" IS a real
        # row in the registry (unlike "no-such-host"), but it claims no
        # capabilities and maps no probes. This path -- a known host with an
        # empty `probes` mapping -- was otherwise never exercised.
        with tempfile.TemporaryDirectory() as target:
            art = host_probes.run_probes("gemini", target)
            self.assertIsNotNone(hosts.spec("gemini"))
            self.assertEqual({hosts.UNKNOWN},
                             {r["state"] for r in art["capabilities"].values()})
            self.assertEqual(
                host_probes.SHADOW_SHELL_SCAN,
                art["capabilities"][hosts.TOOL_POLICY_ENFORCED]["by"])
            for capability in hosts.CAPABILITIES:
                if capability == hosts.TOOL_POLICY_ENFORCED:
                    continue
                with self.subTest(capability=capability):
                    self.assertIsNone(art["capabilities"][capability]["by"])

    def test_when_both_probes_refute_the_first_recorded_wins_the_tie(self):
        # Important-2: an empty registration dir makes registered-shell-tools
        # refute, and an unreadable scope dir makes shadow-shell-scan refute
        # -- both at once. Both facts are true, and BOTH survive into
        # `detail` (joined) -- only `by` picks a single winner (the first
        # recorded, i.e. registered-shell-tools, since run_probes walks the
        # registry's `probes` mapping before the unconditional
        # shadow-shell-scan call). Fix round 1 on #1344 F3a: reporting only
        # the first probe's detail silently dropped the shadow-shell finding
        # from the artifact on exactly the machines (no registered shells)
        # where a hostile target is most likely to be reviewed -- this test
        # must fail if that regresses.
        import getpass
        if getpass.getuser() == "root":
            self.skipTest("running as root, os.listdir ignores permissions")
        with tempfile.TemporaryDirectory() as target, \
                tempfile.TemporaryDirectory() as registration:
            # registration dir exists but is empty -> registered-shell-tools
            # refutes ("no shell at ..." for every driver role).
            shadow = os.path.join(target, ".claude", "agents")
            os.makedirs(shadow)
            os.chmod(shadow, 0o000)
            try:
                art = host_probes.run_probes("claude", target,
                                             registration_dir=registration)
            finally:
                os.chmod(shadow, 0o700)
            row = art["capabilities"][hosts.TOOL_POLICY_ENFORCED]
            self.assertEqual(hosts.REFUTED, row["state"])
            self.assertEqual(host_probes.REGISTERED_SHELL_TOOLS, row["by"])
            # The JOIN, not just the winner. Asserting only on the first
            # probe's text passes whether or not the join exists -- and
            # losing the join is precisely how a shadowing target went
            # undisclosed on a machine with no registered shells (fix round
            # 1). "shadow" appears only in shadow-shell-scan's own detail
            # ("...so shadowing could not be ruled out"), never in
            # registered-shell-tools' "no shell at ..." text, so this fails
            # if the join is reverted to reporting a single winner.
            self.assertIn("no shell at", row["detail"])
            self.assertIn("shadow", row["detail"])
            self.assertEqual(host_probes.REGISTERED_SHELL_TOOLS, row["by"])

    def test_the_registry_mapping_drives_which_capability_a_probe_lands_on(self):
        # Important-4: `HostSpec.probes` must DRIVE dispatch, not just gate a
        # hard-coded capability. Every REAL row in hosts.HOSTS happens to map
        # registered-shell-tools to tool_policy_enforced, so a hard-coded
        # capability would pass every other test in this file. A synthetic
        # row that maps it to usage_ledger instead is the only way to prove
        # the mapping is load-bearing.
        from unittest import mock
        from scripts import dispatch
        mismatched = "probe-mismatch"
        row = hosts.HostSpec(
            name=mismatched, claims=frozenset({hosts.USAGE_LEDGER}),
            shell_format="md",
            probes={hosts.USAGE_LEDGER: host_probes.REGISTERED_SHELL_TOOLS})
        with mock.patch.dict(hosts.HOSTS, {mismatched: row}), \
                tempfile.TemporaryDirectory() as target, \
                tempfile.TemporaryDirectory() as registration:
            for role in host_probes.DRIVER_ROLES:
                role_file = dispatch.ROLE_FILES[role]
                allowed = dispatch.load_template(role_file)[0]["tool_policy"]["allowed"]
                _shell(registration,
                       dispatch.registered_agent_filename(mismatched, role_file),
                       allowed)
            art = host_probes.run_probes(mismatched, target,
                                         registration_dir=registration)
            usage = art["capabilities"][hosts.USAGE_LEDGER]
            self.assertEqual(hosts.PROVEN, usage["state"])
            self.assertEqual(host_probes.REGISTERED_SHELL_TOOLS, usage["by"])
            # And NOT under the hard-coded capability the old code used.
            tpe = art["capabilities"][hosts.TOOL_POLICY_ENFORCED]
            self.assertNotEqual(host_probes.REGISTERED_SHELL_TOOLS, tpe["by"])

    def test_an_unrecognised_probe_id_resolves_to_unknown_with_a_reason(self):
        from unittest import mock
        ghost = "probe-ghost"
        row = hosts.HostSpec(
            name=ghost, claims=frozenset({hosts.ARTIFACT_WRITE_GUARD}),
            probes={hosts.ARTIFACT_WRITE_GUARD: "no-such-probe"})
        with mock.patch.dict(hosts.HOSTS, {ghost: row}), \
                tempfile.TemporaryDirectory() as target:
            art = host_probes.run_probes(ghost, target)
            result = art["capabilities"][hosts.ARTIFACT_WRITE_GUARD]
            self.assertEqual(hosts.UNKNOWN, result["state"])
            self.assertIsNone(result["by"])
            self.assertIn("no implementation", result["detail"])


class TestTheEvidenceLoader(unittest.TestCase):

    def test_an_absent_artifact_reads_as_no_evidence(self):
        # Fail-closed by absence (9.2): {} feeds posture(), which returns
        # all-unknown, which means nothing is enforced.
        from scripts.phases import runio
        with tempfile.TemporaryDirectory() as review_root:
            self.assertEqual({}, runio.host_evidence(review_root))
            self.assertEqual(
                {hosts.UNKNOWN},
                set(hosts.posture("claude",
                                  runio.host_evidence(review_root)).values()))

    def test_a_corrupt_artifact_reads_as_no_evidence(self):
        from scripts.phases import runio
        with tempfile.TemporaryDirectory() as review_root:
            path = runio._pano(review_root, runio.HOST_CAPABILITIES)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{ this is not json")
            self.assertEqual({}, runio.host_evidence(review_root))

    def test_a_present_artifact_reads_as_its_capabilities_map_not_the_envelope(self):
        # The trap this task's brief calls out by name: `host_evidence` must
        # return the inner `capabilities` map, not the whole artifact.
        # hosts.posture() reads `evidence.get(capability)` -- handing it the
        # envelope would make every capability resolve UNKNOWN, because the
        # envelope's top level has no key named e.g. tool_policy_enforced (it
        # has "schema_version", "host", "probed_at", "capabilities" instead).
        # Neither of the two tests above can catch this: an absent or corrupt
        # artifact collapses to {} under BOTH the correct and the trap form.
        from scripts.phases import runio
        with tempfile.TemporaryDirectory() as review_root:
            artifact = {
                "schema_version": 1, "host": "claude",
                "probed_at": "2026-09-10T00:00:00Z",
                "capabilities": {
                    hosts.TOOL_POLICY_ENFORCED: {
                        "state": hosts.PROVEN, "by": "registered-shell-tools",
                        "detail": "ok"},
                },
            }
            runio._write_json(runio._pano(review_root, runio.HOST_CAPABILITIES),
                              artifact)
            evidence = runio.host_evidence(review_root)
            self.assertEqual(artifact["capabilities"], evidence)
            self.assertNotIn("schema_version", evidence)
            self.assertEqual(
                hosts.PROVEN,
                hosts.posture("claude", evidence)[hosts.TOOL_POLICY_ENFORCED])

    def test_a_truthy_non_mapping_body_reads_as_no_evidence(self):
        # I3. The docstring promised fail-closed; `or {}` delivered it only for
        # a FALSY parse. A body that parsed to a truthy non-mapping went into
        # `.get` and raised AttributeError -- measured on the pre-fix tree for
        # all three of these -- which is not failing closed, it is failing. The
        # artifact lives at a `.panopticon` path a hostile target can
        # pre-commit, and `requests.require_unenforced_ack` consumes this
        # output raw at requests.py:209.
        from scripts.phases import runio
        for body in ("[1,2]", '"hello"', "5", "true"):
            with self.subTest(body=body):
                with tempfile.TemporaryDirectory() as review_root:
                    path = runio._pano(review_root, runio.HOST_CAPABILITIES)
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "w", encoding="utf-8") as fh:
                        fh.write(body)
                    self.assertEqual({}, runio.host_evidence(review_root))

    def test_a_non_mapping_capabilities_value_reads_as_no_evidence(self):
        # The subtler half: the envelope IS a dict, so the isinstance check on
        # the body alone passes it -- and the pre-fix loader then RETURNED the
        # integer 7 as this run's evidence. `hosts.posture` would go on to call
        # `.get` on it. Both shapes have to be checked, which is why the fix is
        # two isinstance tests rather than one.
        from scripts.phases import runio
        for value in (7, "capabilities", [1, 2], None):
            with self.subTest(value=value):
                with tempfile.TemporaryDirectory() as review_root:
                    runio._write_json(
                        runio._pano(review_root, runio.HOST_CAPABILITIES),
                        {"schema_version": 1, "host": "claude",
                         "capabilities": value})
                    evidence = runio.host_evidence(review_root)
                    self.assertEqual({}, evidence)
                    # and the consumer stays fail-closed on it
                    self.assertEqual(
                        {hosts.UNKNOWN},
                        set(hosts.posture("claude", evidence).values()))
