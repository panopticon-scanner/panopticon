import contextlib
import json
import os
import shutil
import tempfile
import threading
import unittest
from unittest import mock

from scripts import dispatch, host_probes, hosts, model_resolver, write_guard_hook


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

    def test_the_driver_roles_are_every_role_the_driver_dispatches(self):
        # #1606: `advisor` was excluded on the claim that the host, not the
        # driver, dispatches it. False -- phases/verify.py::_tool_verify_entry
        # writes a driver entry with agent=panopticon-advisor whenever
        # tool_policy_enforced is PROVEN, a proof this probe established from
        # the OTHER three shells. Derived from ROLE_FILES so no hand-kept
        # tuple can quietly leave a dispatched role unchecked again.
        from scripts import dispatch
        self.assertEqual(tuple(sorted(dispatch.ROLE_FILES)), host_probes.DRIVER_ROLES)
        self.assertIn("advisor", host_probes.DRIVER_ROLES)

    def test_a_missing_advisor_shell_is_refuted(self):
        # The fixture #1606 is about: three perfect shells, no advisor shell.
        # Before the fix this was PROVEN and tool-verify dispatched
        # panopticon-advisor enforced into a shell that did not exist.
        from scripts import dispatch
        with tempfile.TemporaryDirectory() as d:
            self._fully_registered(d)
            os.remove(os.path.join(
                d, dispatch.registered_agent_filename("claude", "advisor.md")))
            state, _by, detail = host_probes.probe_registered_shell_tools("claude", d)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("advisor: no shell at", detail)

    def test_a_complete_correct_registration_is_proven(self):
        with tempfile.TemporaryDirectory() as d:
            self._fully_registered(d)
            state, by, detail = host_probes.probe_registered_shell_tools("claude", d)
            self.assertEqual(hosts.PROVEN, state)
            self.assertEqual("registered-shell-tools", by)
            self.assertIn("%d/%d" % (len(host_probes.DRIVER_ROLES),
                                     len(host_probes.DRIVER_ROLES)), detail)

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


def _model_shell(directory, host, role_file, model, tools="Read, Grep, Glob",
                 body_decoy="NOT-FRONTMATTER"):
    """A registered shell that BINDS a model, in claude's emitted shape.

    `body_decoy` lands in the charter BODY as `model: <body_decoy>`, never in
    the frontmatter -- it exists so a test can plant a value there that must
    be ignored (the default) or, for the fenced-scan regression test, one
    that must NOT be picked up even though it happens to be the correct one.
    """
    path = os.path.join(directory, dispatch.registered_agent_filename(host, role_file))
    fm = ["---", "name: %s" % dispatch.registered_agent_name(role_file),
          "description: fixture", "tools: %s" % tools]
    if model is not None:
        fm.append("model: %s" % model)
    fm += ["---", "", "charter body", "model: %s" % body_decoy]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(fm) + "\n")
    return path


class TestEntryModelBoundProbe(unittest.TestCase):
    """#1344 F4: registration must bind the model dispatch resolves, or an
    enforced dispatch runs on the shell's choice while the entry claims another.
    """

    def _register_all(self, d, host="claude"):
        for role, role_file in dispatch.ROLE_FILES.items():
            _model_shell(d, host, role_file,
                         model_resolver.resolve_model(host, role)["model"])

    def test_every_registered_shell_binding_the_resolved_model_is_proven(self):
        with tempfile.TemporaryDirectory() as d:
            self._register_all(d)
            state, by, detail = host_probes.probe_entry_model_bound("claude", d)
        self.assertEqual((hosts.PROVEN, host_probes.ENTRY_MODEL_BOUND), (state, by))
        self.assertIn("%d/%d" % (len(dispatch.ROLE_FILES), len(dispatch.ROLE_FILES)), detail)

    def test_an_ambient_override_the_shell_cannot_see_is_refuted(self):
        # THE case the probe exists for: resolve_model honours
        # PANOPTICON_MODEL_*, registration_model does not (by design), so the
        # entry requests one model and the enforced shell runs another.
        with tempfile.TemporaryDirectory() as d:
            self._register_all(d)
            with mock.patch.dict(os.environ, {"PANOPTICON_MODEL_DOMAIN_PANEL": "OVERRIDE-X"}):
                state, by, detail = host_probes.probe_entry_model_bound("claude", d)
        self.assertEqual((hosts.REFUTED, host_probes.ENTRY_MODEL_BOUND), (state, by))
        self.assertIn("domain_panel", detail)
        self.assertIn("OVERRIDE-X", detail)

    def test_a_shell_that_binds_no_model_is_refuted_not_unknown(self):
        # No `model:` line means the host inherits the SESSION's model for that
        # role -- which silently overrides whatever the entry requested. That
        # is measured, not unmeasured: refuted.
        with tempfile.TemporaryDirectory() as d:
            self._register_all(d)
            _model_shell(d, "claude", "domain-advisor.md", model=None)
            state, _by, detail = host_probes.probe_entry_model_bound("claude", d)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("domain_advisor", detail)

    def test_a_model_line_in_the_charter_body_does_not_rescue_a_shell_that_binds_none(self):
        # The obvious version of this test -- register every role correctly,
        # then check PROVEN -- cannot fail its own mutation: every shell
        # _register_all writes binds a frontmatter model, so
        # `_frontmatter_model` returns at that match before it ever reaches
        # the closing fence, and a scanner that read past the fence would
        # never be exercised by any fixture here.
        #
        # Overwrite ONE shell instead so it binds NO frontmatter model, but
        # its BODY carries the CORRECT resolved value for that same role.
        # The frontmatter-only scanner must still call this REFUTED (no
        # binding was made); only a scanner that reads past the closing fence
        # would be fooled into reporting it PROVEN off the body's decoy.
        with tempfile.TemporaryDirectory() as d:
            self._register_all(d)
            resolved = model_resolver.resolve_model("claude", "domain_advisor")["model"]
            _model_shell(d, "claude", "domain-advisor.md", model=None,
                         body_decoy=resolved)
            state, _by, detail = host_probes.probe_entry_model_bound("claude", d)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("domain_advisor", detail)

    def test_no_registered_shell_is_unknown_never_vacuously_proven(self):
        with tempfile.TemporaryDirectory() as d:
            state, by, _detail = host_probes.probe_entry_model_bound("claude", d)
        self.assertEqual((hosts.UNKNOWN, host_probes.ENTRY_MODEL_BOUND), (state, by))

    def test_a_missing_registration_directory_is_unknown(self):
        nonexistent = os.path.join(tempfile.gettempdir(), "no-such-dir-%d" % os.getpid())
        state, _by, _detail = host_probes.probe_entry_model_bound("claude", nonexistent)
        self.assertEqual(hosts.UNKNOWN, state)

    def test_a_partially_registered_host_is_proven_on_what_is_registered(self):
        # An unregistered role dispatches general-purpose and carries its model
        # on the entry itself (docs/PANOPTICON.md), so it cannot be silently
        # overridden by registration -- there is none. It is named, not hidden.
        with tempfile.TemporaryDirectory() as d:
            _model_shell(d, "claude", "domain-panel.md",
                         model_resolver.resolve_model("claude", "domain_panel")["model"])
            state, _by, detail = host_probes.probe_entry_model_bound("claude", d)
        self.assertEqual(hosts.PROVEN, state)
        self.assertIn("1/%d" % len(dispatch.ROLE_FILES), detail)
        self.assertIn("scout", detail)          # the absent ones are listed

    def test_a_host_without_shells_is_unknown(self):
        state, by, _detail = host_probes.probe_entry_model_bound("gemini")
        self.assertEqual((hosts.UNKNOWN, None), (state, by))

    def test_the_probe_compares_against_resolve_model_not_the_profile_file(self):
        # Sentinel: patch the resolver to disagree with every shell. If the
        # probe read model-profiles.yml or registration_model directly, the
        # shells (written from the real resolver) would still match and this
        # would pass while the probe measured the wrong thing.
        with tempfile.TemporaryDirectory() as d:
            self._register_all(d)
            with mock.patch.object(model_resolver, "resolve_model",
                                   return_value={"model": "SENTINEL"}):
                state, _by, detail = host_probes.probe_entry_model_bound("claude", d)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("SENTINEL", detail)

    def test_the_registry_names_this_probe_for_claude(self):
        self.assertEqual(host_probes.ENTRY_MODEL_BOUND,
                         hosts.spec("claude").probes[hosts.MODEL_BINDING])

    def test_run_probes_records_it_under_model_binding(self):
        # Mirror the existing run_probes test's fixture arguments in this file
        # (registration_dir, session_root, home all pointed at temp dirs so no
        # live state is touched).
        with tempfile.TemporaryDirectory() as reg, \
             tempfile.TemporaryDirectory() as target, \
             tempfile.TemporaryDirectory() as home:
            self._register_all(reg)
            env = host_probes.run_probes("claude", target, session_root=target,
                                         registration_dir=reg, home=home)
        row = env["capabilities"][hosts.MODEL_BINDING]
        self.assertEqual(host_probes.ENTRY_MODEL_BOUND, row["by"])
        self.assertIn(row["state"], (hosts.PROVEN, hosts.REFUTED))   # measured, not unknown

    def test_a_freshly_emitted_registration_proves(self):
        # The probe parses a format dispatch.emit_host_agents writes. Every
        # other fixture here hand-writes shells; this one uses the real
        # emitter so a change to the emitted frontmatter (quoting, indent,
        # key order) cannot silently flip a correct machine to REFUTED.
        with tempfile.TemporaryDirectory() as d:
            dispatch.emit_host_agents("claude", d)
            state, _by, _detail = host_probes.probe_entry_model_bound("claude", d)
        self.assertEqual(hosts.PROVEN, state)

    def test_probe_ids_name_exactly_the_shipped_runners(self):
        # The retirement bar (tests/test_generic_retirement_bar.py) reads
        # PROBE_IDS as "the shipped probes" (spec 8.1). A runner that exists
        # but is not listed would make the bar stricter than reality; a listed
        # id with no runner would make it vacuous. run_probes refuses to build
        # a table that disagrees, so the constant cannot rot in either direction.
        self.assertEqual(sorted(host_probes.PROBE_IDS),
                         sorted({host_probes.REGISTERED_SHELL_TOOLS,
                                 host_probes.WRITE_GUARD_ARMED,
                                 host_probes.TRANSCRIPT_DIR,
                                 host_probes.ENTRY_MODEL_BOUND,
                                 host_probes.READ_GUARD_ARMED,
                                 # #1344 kimi family PR: the five probes the
                                 # kimi row maps its five claims to.
                                 host_probes.KIMI_SHELL_SURFACE,
                                 host_probes.KIMI_READ_GUARD,
                                 host_probes.KIMI_WRITE_GUARD,
                                 host_probes.KIMI_MODEL_ALIAS,
                                 host_probes.KIMI_USAGE_WIRE}))
        with tempfile.TemporaryDirectory() as reg, \
             tempfile.TemporaryDirectory() as target, \
             tempfile.TemporaryDirectory() as home:
            with mock.patch.object(host_probes, "PROBE_IDS", host_probes.PROBE_IDS[:-1]):
                with self.assertRaises(RuntimeError):
                    host_probes.run_probes("claude", target, session_root=target,
                                           registration_dir=reg, home=home)

    def test_every_probe_id_in_the_registry_is_shipped(self):
        # spec 9.1 registry totality, the other half: hosts.py cannot import
        # host_probes (purity), so the join is asserted here.
        rows = [row for row in hosts.HOSTS.values() if row.probes]
        self.assertTrue(rows)                                    # guards the guard
        for row in rows:
            for capability, probe_id in row.probes.items():
                with self.subTest(host=row.name, capability=capability):
                    self.assertIn(probe_id, host_probes.PROBE_IDS)

    def test_every_registry_mapping_names_the_probe_that_measures_it(self):
        # Item 1: `in PROBE_IDS` alone lets a row map a capability to a
        # shipped probe that proves something ELSE (the retirement bar's
        # gap this closes). Every registry (capability, probe_id) pair must
        # also satisfy PROBE_CAPABILITY[probe_id] == capability.
        rows = [row for row in hosts.HOSTS.values() if row.probes]
        self.assertTrue(rows)                                    # guards the guard
        for row in rows:
            for capability, probe_id in row.probes.items():
                with self.subTest(host=row.name, capability=capability):
                    self.assertEqual(capability, host_probes.PROBE_CAPABILITY[probe_id])

    def test_probe_capability_covers_exactly_the_shipped_probes(self):
        self.assertEqual(set(host_probes.PROBE_CAPABILITY), set(host_probes.PROBE_IDS))


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

    def test_an_explicit_settings_path_is_the_subject_and_need_not_exist_yet(self):
        # Spec 5.4 / R-P6-5: in headless mode the runner CREATES the settings
        # file after the first probe, so the probe must not demand it exists;
        # it demands the directory can be written. Same verdict before and
        # after the file appears, or posture drift would refuse iteration 2.
        with tempfile.TemporaryDirectory() as run_dir:
            path = os.path.join(run_dir, "host-settings.json")
            state1, by, detail1 = host_probes.probe_write_guard_armed("claude", settings_path=path)
            self.assertEqual(hosts.PROVEN, state1)
            self.assertIn(path, detail1)
            with open(path, "w") as fh:
                fh.write("{}")
            state2, _by, _d = host_probes.probe_write_guard_armed("claude", settings_path=path)
            self.assertEqual(state1, state2)

    def test_an_unwritable_headless_directory_refutes(self):
        # try/finally rather than addCleanup, matching this class's own
        # test_an_unwritable_settings_root_is_refuted above: the `with`
        # TemporaryDirectory block ends INSIDE this method, so an addCleanup
        # chmod would run after `run_dir` (and `locked` within it) is already
        # removed, raising a spurious FileNotFoundError -- measured, not
        # assumed (shutil.rmtree deletes a 0500 child fine; it is the
        # PARENT's write bit that governs unlink, not the child's own mode).
        with tempfile.TemporaryDirectory() as run_dir:
            locked = os.path.join(run_dir, "ro"); os.makedirs(locked); os.chmod(locked, 0o500)
            try:
                if os.access(locked, os.W_OK):
                    self.skipTest("running as a user who can write a 0500 directory")
                state, _by, detail = host_probes.probe_write_guard_armed(
                    "claude", settings_path=os.path.join(locked, "host-settings.json"))
            finally:
                os.chmod(locked, 0o700)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn("not writable", detail)

    def test_the_probe_reads_its_settings_path_argument(self):
        # Mutation gate (spec 7.6): a probe that ignores settings_path must
        # fail this. The patch is signature-conditional: it raises ONLY for
        # the probe's session-root fallback call, `_resolve(None, None,
        # <anything>)`; the sandbox round trip's own explicit-path calls
        # (through install()/guard_state()/uninstall()) pass through to the
        # real function, since it legitimately calls _resolve with explicit
        # paths and an always-raise patch would fail this test falsely.
        real_resolve = host_probes.write_guard_hook._resolve
        def fallback_only(settings_path, allowlist_path, session_root):
            if settings_path is None and allowlist_path is None:
                raise AssertionError(
                    "must not fall back to _resolve when settings_path is given")
            return real_resolve(settings_path, allowlist_path, session_root)
        with tempfile.TemporaryDirectory() as run_dir:
            with mock.patch.object(host_probes.write_guard_hook, "_resolve",
                                   side_effect=fallback_only):
                state, _by, _d = host_probes.probe_write_guard_armed(
                    "claude", settings_path=os.path.join(run_dir, "host-settings.json"))
            self.assertEqual(hosts.PROVEN, state)


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
        # key. read_scope_confined has a probe now too (read-guard-armed,
        # plan 5); model_binding gained one in F4 (entry-model-bound).
        # `registration_dir` is pinned
        # to an empty temp dir -- not left to default to this machine's real
        # ~/.claude/agents -- so the probe never touches live state and the
        # assertions stay broad (any real STATE) rather than depending on
        # what happens to be registered on whichever machine runs this.
        with tempfile.TemporaryDirectory() as target, \
                tempfile.TemporaryDirectory() as registration:
            art = host_probes.run_probes("claude", target,
                                         registration_dir=registration)
            self.assertEqual(sorted(hosts.CAPABILITIES),
                             sorted(art["capabilities"]))
            for capability in hosts.CAPABILITIES:
                with self.subTest(capability=capability):
                    row = art["capabilities"][capability]
                    self.assertIn(row["state"], hosts.STATES)
                    self.assertTrue(row["detail"])

    def test_the_unprobed_capability_says_why(self):
        # Plan 5 shipped read-guard-armed for claude, so no capability is
        # probe-less by design any more (_NO_PROBE is empty); a host that
        # does not CLAIM one still gets the honest "nothing to prove" row.
        with tempfile.TemporaryDirectory() as target:
            art = host_probes.run_probes("gemini", target)
            row = art["capabilities"][hosts.READ_SCOPE_CONFINED]
            self.assertEqual(hosts.UNKNOWN, row["state"])
            self.assertIsNone(row["by"])
            self.assertIn("does not claim", row["detail"])
        self.assertEqual({}, host_probes._NO_PROBE)

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
        with tempfile.TemporaryDirectory() as target, \
                tempfile.TemporaryDirectory() as registration:
            art = host_probes.run_probes("claude", target,
                                         registration_dir=registration)
            self.assertEqual(1, art["schema_version"])
            self.assertEqual("claude", art["host"])
            self.assertTrue(art["probed_at"])

    def test_capabilities_of_ignores_the_timestamp(self):
        # The comparison on resume must not fire merely because time passed.
        with tempfile.TemporaryDirectory() as target, \
                tempfile.TemporaryDirectory() as registration:
            first = host_probes.run_probes("claude", target,
                                           registration_dir=registration)
            second = dict(first, probed_at="1999-01-01T00:00:00Z")
            self.assertEqual(host_probes.capabilities_of(first),
                             host_probes.capabilities_of(second))

    def test_capabilities_of_fails_closed_on_a_truthy_non_mapping_artifact(self):
        # R18: `(artifact or {})` only catches the FALSY case. A truthy
        # non-dict -- a non-empty list, a non-empty string, a nonzero number
        # -- sailed past that `or` unchanged and `.get("capabilities")` on it
        # raised AttributeError. The caller is
        # `driver._establish_host_posture`, feeding this `stored` --
        # `runio._load_json()`'s parse of host-capabilities.json, a file a
        # hostile target can plant or truncate -- so a crash here is a
        # mid-run traceback rather than a refusal. `hosts.posture()` and
        # `runio.host_evidence()` were both hardened against exactly this
        # shape already; this was the spot still missed. The falsy cases
        # ([], 0, "", False, None) already degraded to {} before this fix;
        # they are included here so the fix is proven not to have narrowed
        # that existing behaviour.
        for bad in (["not", "a", "dict"], "not-a-dict", 7,
                    [], 0, "", False, None):
            with self.subTest(artifact=bad):
                self.assertEqual({}, host_probes.capabilities_of(bad))

    def test_capabilities_of_fails_closed_on_a_truthy_non_mapping_entry(self):
        # Fix round 1 / F2: the outer `artifact` shape was hardened above, but
        # `(body or {}).get("state")` was left on its original guard, so a
        # WELL-FORMED artifact whose per-capability VALUE is a truthy non-dict
        # -- {"capabilities": {"tool_policy_enforced": "pwned"}} -- still
        # raised AttributeError. Same untrusted file
        # (host-capabilities.json), same direct caller
        # (driver._establish_host_posture, which reads this function rather
        # than going through hosts.posture()'s own per-entry guard). A
        # malformed entry must resolve to state `None` for that capability,
        # not raise.
        for bad in (["not", "a", "dict"], "not-a-dict", 7):
            with self.subTest(entry=bad):
                artifact = {"capabilities": {hosts.TOOL_POLICY_ENFORCED: bad}}
                self.assertEqual({hosts.TOOL_POLICY_ENFORCED: None},
                                 host_probes.capabilities_of(artifact))

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

    def test_run_probes_hands_settings_path_to_both_guard_probes(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(host_probes, "probe_write_guard_armed",
                               return_value=(hosts.PROVEN, "write-guard-armed", "x")) as w, \
             mock.patch.object(host_probes, "probe_read_guard_armed",
                               return_value=(hosts.PROVEN, "read-guard-armed", "x")) as r:
            host_probes.run_probes("claude", d, session_root=d, settings_path="/run/host-settings.json",
                                   shadow=(hosts.UNKNOWN, None, "fixture"))
        self.assertEqual(w.call_args.kwargs.get("settings_path"), "/run/host-settings.json")
        self.assertEqual(r.call_args.kwargs.get("settings_path"), "/run/host-settings.json")


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


class TestReadGuardArmedProbe(unittest.TestCase):
    """Plan 5: proves the host CAN bind a subagent to its entry and confine
    its reads -- in a sandbox, at run start, when the guard is legitimately
    not armed (the host arms it per fan-out, like the write guard)."""

    def _session_root(self, root):
        claude = os.path.join(root, ".claude")
        os.makedirs(claude, exist_ok=True)
        with open(os.path.join(claude, "settings.local.json"), "w", encoding="utf-8") as fh:
            fh.write("{}")
        return claude

    def test_a_working_guard_and_a_writable_settings_root_is_proven(self):
        with tempfile.TemporaryDirectory() as session_root:
            self._session_root(session_root)
            state, by, detail = host_probes.probe_read_guard_armed("claude", session_root=session_root)
            self.assertEqual(hosts.PROVEN, state)
            self.assertEqual("read-guard-armed", by)
            self.assertIn(session_root, detail)
            self.assertIn("14 rows", detail)

    def test_it_does_not_require_the_guard_to_be_armed_right_now(self):
        from scripts import read_guard_hook
        with tempfile.TemporaryDirectory() as session_root:
            self._session_root(session_root)
            self.assertFalse(read_guard_hook.guard_state(session_root=session_root)["armed"])
            state, _by, _detail = host_probes.probe_read_guard_armed("claude", session_root=session_root)
            self.assertEqual(hosts.PROVEN, state)

    def test_a_missing_settings_file_is_refuted(self):
        with tempfile.TemporaryDirectory() as session_root:
            os.makedirs(os.path.join(session_root, ".claude"), exist_ok=True)
            state, _by, detail = host_probes.probe_read_guard_armed("claude", session_root=session_root)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn("settings.local.json", detail)

    def test_an_unwritable_settings_root_is_refuted(self):
        with tempfile.TemporaryDirectory() as session_root:
            claude_dir = self._session_root(session_root)
            os.chmod(claude_dir, 0o500)
            try:
                state, _by, detail = host_probes.probe_read_guard_armed("claude", session_root=session_root)
            finally:
                os.chmod(claude_dir, 0o700)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn(claude_dir, detail)

    def test_a_host_that_claims_no_read_confinement_is_unknown(self):
        # kimi left this tuple in the kimi family PR (#1344): it now claims
        # READ_SCOPE_CONFINED and ships its own probe (kimi-read-guard-armed),
        # so the claude-shaped probe must never run for it.
        for name in ("gemini", "generic", "codex"):
            with self.subTest(host=name):
                state, by, _detail = host_probes.probe_read_guard_armed(name)
                self.assertEqual(hosts.UNKNOWN, state)
                self.assertIsNone(by)

    def test_each_round_trip_row_can_refute(self):
        # Spec 5: a probe that cannot fail is the defect this epic exists to
        # prevent. Break the guard three ways; each must REFUTE and name a row.
        from scripts import read_guard_hook
        with tempfile.TemporaryDirectory() as session_root:
            self._session_root(session_root)
            cases = {
                "decide allows everything": mock.patch.object(read_guard_hook, "decide", return_value=(True, "")),
                "decide denies everything": mock.patch.object(read_guard_hook, "decide", return_value=(False, "x")),
                "bind never binds": mock.patch.object(read_guard_hook, "bind", return_value=None),
            }
            for name, patch in cases.items():
                with self.subTest(case=name), patch:
                    state, by, detail = host_probes.probe_read_guard_armed("claude", session_root=session_root)
                    self.assertEqual(hosts.REFUTED, state)
                    self.assertEqual("read-guard-armed", by)
                    self.assertIn("the guard", detail)

    def test_the_probe_leaves_the_sessions_settings_untouched(self):
        with tempfile.TemporaryDirectory() as session_root:
            self._session_root(session_root)
            settings = os.path.join(session_root, ".claude", "settings.local.json")
            host_probes.probe_read_guard_armed("claude", session_root=session_root)
            self.assertEqual("{}", open(settings, encoding="utf-8").read())
            self.assertFalse(os.path.exists(os.path.join(session_root, ".panopticon", "read-scope.json")))

    def test_run_probes_reports_read_scope_confined_by_this_probe_on_claude(self):
        with tempfile.TemporaryDirectory() as target, tempfile.TemporaryDirectory() as registration, \
                tempfile.TemporaryDirectory() as session_root:
            self._session_root(session_root)
            art = host_probes.run_probes("claude", target, session_root=session_root,
                                         registration_dir=registration)
            row = art["capabilities"][hosts.READ_SCOPE_CONFINED]
            self.assertEqual(hosts.PROVEN, row["state"])
            self.assertEqual("read-guard-armed", row["by"])

    def test_the_round_trip_proves_the_env_binding(self):
        # Spec 5.3 / 7.5: the probe drives an env-bound payload (allowed inside,
        # denied outside) and an agent_type-only payload (denied). Pinned by
        # mutating adjudicate to ignore `env` and watching the verdict flip.
        from scripts import read_guard_hook
        ok, detail = host_probes._round_trip_confines_reads()
        self.assertTrue(ok, detail)
        real = read_guard_hook.adjudicate
        def ignores_env(payload, scope_path, env=None):
            return real(payload, scope_path, env={})
        with mock.patch.object(read_guard_hook, "adjudicate", ignores_env):
            ok, detail = host_probes._round_trip_confines_reads()
        self.assertFalse(ok)
        self.assertIn("env", detail)

    def test_an_explicit_settings_path_is_the_subject_and_need_not_exist_yet(self):
        # Spec 5.4 / R-P6-5: in headless mode the runner CREATES the settings
        # file after the first probe, so the probe must not demand it exists;
        # it demands the directory can be written. Same verdict before and
        # after the file appears, or posture drift would refuse iteration 2.
        with tempfile.TemporaryDirectory() as run_dir:
            path = os.path.join(run_dir, "host-settings.json")
            state1, by, detail1 = host_probes.probe_read_guard_armed("claude", settings_path=path)
            self.assertEqual(hosts.PROVEN, state1)
            self.assertIn(path, detail1)
            with open(path, "w") as fh:
                fh.write("{}")
            state2, _by, _d = host_probes.probe_read_guard_armed("claude", settings_path=path)
            self.assertEqual(state1, state2)

    def test_an_unwritable_headless_directory_refutes(self):
        # try/finally, not addCleanup -- see the write-probe mirror above.
        with tempfile.TemporaryDirectory() as run_dir:
            locked = os.path.join(run_dir, "ro"); os.makedirs(locked); os.chmod(locked, 0o500)
            try:
                if os.access(locked, os.W_OK):
                    self.skipTest("running as a user who can write a 0500 directory")
                state, _by, detail = host_probes.probe_read_guard_armed(
                    "claude", settings_path=os.path.join(locked, "host-settings.json"))
            finally:
                os.chmod(locked, 0o700)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn("not writable", detail)

    def test_the_probe_reads_its_settings_path_argument(self):
        # Mutation gate (spec 7.6): a probe that ignores settings_path must
        # fail this. Signature-conditional, as for the write probe: raises
        # ONLY for the session-root fallback call `_resolve(None, None,
        # <anything>)`; the sandbox round trip's explicit-path calls pass
        # through to the real function.
        real_resolve = host_probes.read_guard_hook._resolve
        def fallback_only(settings_path, allowlist_path, session_root):
            if settings_path is None and allowlist_path is None:
                raise AssertionError(
                    "must not fall back to _resolve when settings_path is given")
            return real_resolve(settings_path, allowlist_path, session_root)
        with tempfile.TemporaryDirectory() as run_dir:
            with mock.patch.object(host_probes.read_guard_hook, "_resolve",
                                   side_effect=fallback_only):
                state, _by, _d = host_probes.probe_read_guard_armed(
                    "claude", settings_path=os.path.join(run_dir, "host-settings.json"))
            self.assertEqual(hosts.PROVEN, state)


class TestHeadlessSettingsPathIsNamespaceAware(unittest.TestCase):
    def test_setup_namespace_bypasses_the_manifest_tag_lookup(self):
        # Task 6 fix round 1, item 2: setup keeps its OWN setup-manifest.json,
        # never run-manifest.json, so a stale run-manifest.json's tag from an
        # earlier review run must never steer setup's settings path into that
        # run's runs/<tag>/ folder -- unlike namespace=None (a review run),
        # which DOES follow the manifest tag through runio._pano.
        with mock.patch("scripts.phases.runio._run_tag", return_value="stale-tag"):
            self.assertTrue(host_probes.headless_settings_path("/repo", None)
                            .endswith(os.path.join("runs", "stale-tag", "host-settings.json")))
            self.assertEqual(
                host_probes.headless_settings_path("/repo", "setup"),
                os.path.abspath(os.path.join("/repo", ".panopticon", "host-settings.json")))


# --- kimi family probes (#1344) -----------------------------------------------


def _kimi_fully_registered(directory):
    """Register all four driver shells in kimi's block-list dialect, granting
    exactly each template's tool policy (the state --emit-host-agents kimi
    produces)."""
    for role in host_probes.DRIVER_ROLES:
        role_file = dispatch.ROLE_FILES[role]
        allowed = dispatch.load_template(role_file)[0]["tool_policy"]["allowed"]
        _shell(directory, dispatch.registered_agent_filename("kimi", role_file),
               allowed, block_list=True)


class _DoctorFake:
    """A runner= stand-in for `kimi doctor` -- the suite never launches the
    real host binary (FAMILY-PR-GUARDRAILS, Suite rules)."""

    def __init__(self, ok=True, stdout="OK config.toml  /x/config.toml\n"):
        self.ok = ok
        self.stdout = stdout

    def __call__(self, cmd, **kw):
        class P:
            stderr = ""
        p = P()
        p.returncode = 0 if self.ok else 1
        p.stdout = self.stdout if self.ok else "config.toml is invalid TOML"
        return p


class TestKimiShellSurfaceProbe(unittest.TestCase):
    """The kimi tool_policy_enforced probe: template parity AND the installed
    CLI's tool vocabulary, because a name that matches nothing restricts
    nothing (the recorded kimi finding in the guardrails)."""

    def test_fully_registered_shells_on_a_known_version_are_proven(self):
        with tempfile.TemporaryDirectory() as d:
            _kimi_fully_registered(d)
            state, by, detail = host_probes.probe_kimi_shell_surface(
                "kimi", registration_dir=d, version="0.42")
        self.assertEqual(hosts.PROVEN, state)
        self.assertEqual(host_probes.KIMI_SHELL_SURFACE, by)
        self.assertIn("0.42", detail)

    def test_missing_shells_are_refuted_by_the_template_half(self):
        with tempfile.TemporaryDirectory() as d:
            state, by, detail = host_probes.probe_kimi_shell_surface(
                "kimi", registration_dir=d, version="0.42")
        self.assertEqual(hosts.REFUTED, state)
        self.assertEqual(host_probes.KIMI_SHELL_SURFACE, by)
        self.assertIn("no shell", detail)

    def test_a_shell_grant_the_template_forbids_is_refuted(self):
        with tempfile.TemporaryDirectory() as d:
            _kimi_fully_registered(d)
            _shell(d, dispatch.registered_agent_filename("kimi", "scout.md"),
                   ["Read", "Grep", "Glob", "Bash"], block_list=True)
            state, _by, detail = host_probes.probe_kimi_shell_surface(
                "kimi", registration_dir=d, version="0.42")
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("Bash", detail)

    def test_a_tool_name_the_cli_does_not_have_is_refuted(self):
        # The mutation the guardrails demand: narrow the vocabulary table and
        # the probe must flip to refuted rather than wave the shells through.
        with tempfile.TemporaryDirectory() as d:
            _kimi_fully_registered(d)
            import scripts.runners.kimi as kimi_runner
            narrow = {"0.42": kimi_runner.TOOL_VOCABULARY["0.42"] - {"Read", "Bash"}}
            with mock.patch.dict(kimi_runner.TOOL_VOCABULARY, narrow):
                state, _by, detail = host_probes.probe_kimi_shell_surface(
                    "kimi", registration_dir=d, version="0.42")
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("match nothing", detail)

    def test_an_uncovered_cli_version_is_unknown_never_a_guess(self):
        with tempfile.TemporaryDirectory() as d:
            _kimi_fully_registered(d)
            state, _by, detail = host_probes.probe_kimi_shell_surface(
                "kimi", registration_dir=d, version="9.99")
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIn("9.99", detail)

    def test_an_unparseable_cli_version_is_unknown(self):
        def garbage(cmd, **kw):
            class P:
                returncode = 0
                stdout = "not a version"
                stderr = ""
            return P()
        with tempfile.TemporaryDirectory() as d:
            _kimi_fully_registered(d)
            state, _by, _detail = host_probes.probe_kimi_shell_surface(
                "kimi", registration_dir=d, runner=garbage)
        self.assertEqual(hosts.UNKNOWN, state)

    def test_a_host_that_registers_no_shells_is_unknown(self):
        state, by, _detail = host_probes.probe_kimi_shell_surface("gemini", version="0.42")
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIsNone(by)


class TestKimiReadGuardProbe(unittest.TestCase):
    """The kimi read_scope_confined probe: the real guard subprocess round-trip
    (plain python -- not the host binary) plus a faked doctor validation."""

    def test_the_round_trip_and_a_valid_home_are_proven(self):
        state, by, detail = host_probes.probe_kimi_read_guard(
            "kimi", doctor_runner=_DoctorFake())
        self.assertEqual(hosts.PROVEN, state)
        self.assertEqual(host_probes.KIMI_READ_GUARD, by)
        self.assertIn("round-trip", detail)

    def test_a_doctor_rejection_is_refuted(self):
        state, _by, detail = host_probes.probe_kimi_read_guard(
            "kimi", doctor_runner=_DoctorFake(ok=False))
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("doctor", detail)

    def test_a_missing_cli_is_unknown_not_refuted(self):
        def no_binary(cmd, **kw):
            raise FileNotFoundError("kimi")
        state, _by, detail = host_probes.probe_kimi_read_guard(
            "kimi", doctor_runner=no_binary)
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIn("could not run", detail)

    def test_a_guard_failure_is_refuted_with_the_row_named(self):
        # The mutation, at the probe's own seam: a guard that allows an
        # outside read must flip the probe to refuted.
        with mock.patch.object(host_probes, "_guard_round_trip",
                               return_value=(False, "the guard ALLOWED: bound Read outside scope")):
            state, _by, detail = host_probes.probe_kimi_read_guard(
                "kimi", doctor_runner=_DoctorFake())
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("ALLOWED", detail)

    def test_a_host_that_claims_no_read_confinement_is_unknown(self):
        state, by, _detail = host_probes.probe_kimi_read_guard("gemini")
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIsNone(by)


class TestKimiWriteGuardProbe(unittest.TestCase):
    def test_the_write_round_trip_is_proven(self):
        state, by, detail = host_probes.probe_kimi_write_guard("kimi")
        self.assertEqual(hosts.PROVEN, state)
        self.assertEqual(host_probes.KIMI_WRITE_GUARD, by)
        self.assertIn("round-trip", detail)

    def test_a_guard_failure_is_refuted_with_the_row_named(self):
        with mock.patch.object(host_probes, "_guard_round_trip",
                               return_value=(False, "the guard ALLOWED: Write outside the allowlist")):
            state, _by, detail = host_probes.probe_kimi_write_guard("kimi")
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("ALLOWED", detail)

    def test_a_host_that_claims_no_write_guard_is_unknown(self):
        state, by, _detail = host_probes.probe_kimi_write_guard("gemini")
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIsNone(by)


class TestKimiModelAliasProbe(unittest.TestCase):
    CONFIGURED = frozenset({"kimi-code/k3", "kimi-code/kimi-for-coding"})

    def test_every_role_binding_a_configured_alias_is_proven(self):
        state, by, detail = host_probes.probe_kimi_model_alias(
            "kimi", configured=self.CONFIGURED)
        self.assertEqual(hosts.PROVEN, state)
        self.assertEqual(host_probes.KIMI_MODEL_ALIAS, by)
        self.assertIn("kimi-code/k3", detail)

    def test_an_unresolvable_role_is_refuted_and_named(self):
        state, _by, detail = host_probes.probe_kimi_model_alias(
            "kimi", configured=frozenset({"kimi-code/k3"}))
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("scout", detail)

    def test_no_readable_model_table_is_refuted(self):
        state, _by, detail = host_probes.probe_kimi_model_alias("kimi", configured=frozenset())
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("no [models] table", detail)

    def test_a_host_that_claims_no_model_binding_is_unknown(self):
        state, by, _detail = host_probes.probe_kimi_model_alias("gemini")
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIsNone(by)


class TestKimiUsageWireProbe(unittest.TestCase):
    """I4: the ledger's channel is the PER-RUN home's wire files
    (`wire_path(self.kimi_home, session_id)`), not `~/.kimi-code/sessions`,
    which the runner's own KIMI_CODE_HOME override guarantees the children
    never write to. The probe proves the channel the runner reads."""

    def test_the_run_homes_wire_layout_resolves_and_parses(self):
        with tempfile.TemporaryDirectory() as d:
            state, by, detail = host_probes.probe_kimi_usage_wire("kimi", home=d)
        self.assertEqual(hosts.PROVEN, state)
        self.assertEqual(host_probes.KIMI_USAGE_WIRE, by)
        self.assertIn(d, detail)                      # the run home is named
        self.assertIn("wire.jsonl", detail)

    def test_a_layout_wire_path_cannot_resolve_is_refuted(self):
        import scripts.runners.kimi as kimi_runner
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(kimi_runner, "wire_path", return_value=None):
            state, _by, detail = host_probes.probe_kimi_usage_wire("kimi", home=d)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("wire.jsonl", detail)

    def test_a_parser_that_returns_the_wrong_figures_is_refuted(self):
        import scripts.runners.kimi as kimi_runner
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(kimi_runner, "parse_wire", return_value=({}, None)):
            state, _by, detail = host_probes.probe_kimi_usage_wire("kimi", home=d)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("expected", detail)

    def test_a_host_that_claims_no_usage_ledger_is_unknown(self):
        state, by, _detail = host_probes.probe_kimi_usage_wire("gemini")
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIsNone(by)


class TestKimiLaunchGuard(unittest.TestCase):
    """I3: the suite must never launch the real `kimi` binary, and that must be
    STRUCTURAL rather than a property of today's call sites.

    Every kimi spawn resolves its runner from a module attribute
    (one `DEFAULT_RUNNER` per seam module, N1), which
    tests/conftest.py's autouse `_no_live_kimi_launches` swaps for a refusal.
    The probes must let that refusal PROPAGATE: mapping it to UNKNOWN would
    turn "the suite tried to launch kimi" into a quiet probe state.
    """

    def test_run_probes_refuses_to_launch_the_real_binary(self):
        import scripts.runners.kimi as kimi_runner
        with tempfile.TemporaryDirectory() as d:
            home = os.path.join(d, "fixture-home")
            os.makedirs(home)
            with open(os.path.join(home, "config.toml"), "w", encoding="utf-8") as fh:
                fh.write('default_model = "kimi-code/k3"\n')
            registration = os.path.join(d, "agents")
            _kimi_fully_registered(registration)
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": home}), \
                 self.assertRaises(kimi_runner.LaunchRefused) as caught:
                host_probes.run_probes("kimi", d, session_root=d,
                                       registration_dir=registration)
        self.assertIn("kimi", str(caught.exception))

    def test_every_kimi_spawn_seam_carries_one_module_level_DEFAULT_RUNNER(self):
        # N1: #1619's launch guard FINDS seams by AST walk and then asserts
        # `hasattr(module, "DEFAULT_RUNNER")` on each -- one attribute per
        # MODULE, not one per family. A module-scoped name is what survives
        # the rebase; `KIMI_DEFAULT_RUNNER` would fail that test twice.
        import scripts.runners.kimi as kimi_runner
        for module in (host_probes, kimi_runner):
            self.assertTrue(hasattr(module, "DEFAULT_RUNNER"),
                            "%s has no module-level DEFAULT_RUNNER" % module.__name__)
            with self.assertRaises(kimi_runner.LaunchRefused):
                module.DEFAULT_RUNNER(["kimi", "--version"])

    def test_the_runner_resolves_its_launcher_from_the_module_attribute(self):
        import scripts.runners.kimi as kimi_runner
        with tempfile.TemporaryDirectory() as d:
            home = os.path.join(d, "fixture-home")
            os.makedirs(home)
            with open(os.path.join(home, "config.toml"), "w", encoding="utf-8") as fh:
                fh.write('default_model = "kimi-code/k3"\n'
                         '[models."kimi-code/k3"]\nmodel = "k3"\n')
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": home}):
                runner = kimi_runner.Runner("kimi")           # nothing injected
                runner.prepare(os.path.join(d, "run"), review_root=d)
                self.addCleanup(runner.teardown, "complete")  # C1: a temp home
                with self.assertRaises(kimi_runner.LaunchRefused):
                    runner.run_entry({"id": "e1", "model": "secondary",
                                      "prompt": "x"}, {})


def _kimi_armed_config_without(mode):
    """A `build_merged_config` that arms every hook EXCEPT `mode`'s -- the
    mutation the guardrails demand of a probe whose id says "armed"."""
    import scripts.runners.kimi as kimi_runner
    real = kimi_runner.build_merged_config

    def mutated(source, scope_path, allowlist_path, *args, **kwargs):
        merged = real(source, scope_path, allowlist_path, *args, **kwargs)
        merged["hooks"] = [h for h in merged["hooks"]
                           if '" %s "' % mode not in (h.get("command") or "")]
        return merged
    return mutated


class TestKimiGuardArmingIsMeasured(unittest.TestCase):
    """C3: the two probes are named "...-armed", so they must be able to refute
    the ARMING, not only the adjudication. With the hooks deleted from
    `build_merged_config` entirely, both used to return `proven`."""

    def test_a_config_that_arms_no_hooks_refutes_both_probes(self):
        import scripts.runners.kimi as kimi_runner
        with mock.patch.object(kimi_runner, "build_merged_config",
                               side_effect=lambda source, s, a, *x, **k: {"tools": {"disabled": []}}):
            read = host_probes.probe_kimi_read_guard("kimi", doctor_runner=_DoctorFake())
            write = host_probes.probe_kimi_write_guard("kimi")
        for state, by, detail in (read, write):
            self.assertEqual(hosts.REFUTED, state, detail)
            self.assertIn("PreToolUse", detail)

    def test_dropping_the_read_hook_refutes_the_read_probe(self):
        import scripts.runners.kimi as kimi_runner
        with mock.patch.object(kimi_runner, "build_merged_config",
                               side_effect=_kimi_armed_config_without("read")):
            state, _by, detail = host_probes.probe_kimi_read_guard(
                "kimi", doctor_runner=_DoctorFake())
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("Read", detail)

    def test_dropping_the_write_hook_refutes_the_write_probe(self):
        import scripts.runners.kimi as kimi_runner
        with mock.patch.object(kimi_runner, "build_merged_config",
                               side_effect=_kimi_armed_config_without("write")):
            state, _by, detail = host_probes.probe_kimi_write_guard("kimi")
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("Write", detail)

    def test_a_hook_pointing_at_a_nonexistent_script_is_refuted(self):
        import scripts.runners.kimi as kimi_runner
        with mock.patch.object(kimi_runner, "_GUARD", "/nonexistent/kimi_guard_hook.py"):
            state, _by, detail = host_probes.probe_kimi_write_guard("kimi")
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("guard script", detail)

    def test_a_config_the_writer_corrupts_is_refuted(self):
        import scripts.runners.kimi as kimi_runner
        with mock.patch.object(kimi_runner, "dump_toml",
                               side_effect=lambda config: "[[mcp]]\nname = \n"):
            state, _by, detail = host_probes.probe_kimi_write_guard("kimi")
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("valid TOML", detail)

    def test_a_disabled_tool_the_runner_drops_is_refuted(self):
        import scripts.runners.kimi as kimi_runner
        real = kimi_runner.build_merged_config

        def without_disabled(source, scope_path, allowlist_path, *args, **kwargs):
            merged = real(source, scope_path, allowlist_path, *args, **kwargs)
            merged["tools"] = {"disabled": []}
            return merged
        with mock.patch.object(kimi_runner, "build_merged_config",
                               side_effect=without_disabled):
            state, _by, detail = host_probes.probe_kimi_write_guard("kimi")
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("tools.disabled", detail)

    def test_the_armed_detail_names_the_config_it_parsed(self):
        state, _by, detail = host_probes.probe_kimi_write_guard("kimi")
        self.assertEqual(hosts.PROVEN, state)
        self.assertIn("config.toml", detail)

    def test_prepare_refuses_to_run_without_the_guard_script(self):
        import scripts.runners.kimi as kimi_runner
        with tempfile.TemporaryDirectory() as d:
            home = os.path.join(d, "fixture-home")
            os.makedirs(home)
            with open(os.path.join(home, "config.toml"), "w", encoding="utf-8") as fh:
                fh.write('default_model = "kimi-code/k3"\n')
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": home}), \
                 mock.patch.object(kimi_runner, "_GUARD", os.path.join(d, "gone.py")):
                runner = kimi_runner.Runner("kimi")
                with self.assertRaises(RuntimeError) as caught:
                    runner.prepare(os.path.join(d, "run"), review_root=d)
        self.assertIn("gone.py", str(caught.exception))


class TestKimiShellSurfaceIsAnAllowList(unittest.TestCase):
    """I1: the probe's job is not only "every name exists" but "every name is
    accounted for" -- each tool in the CLI's vocabulary is either granted by a
    template or disabled by the per-run config. A tool in neither set is live
    on the default-agent surface of every unenforced entry."""

    def test_the_derived_disabled_set_plus_the_grants_covers_the_vocabulary(self):
        with tempfile.TemporaryDirectory() as d:
            _kimi_fully_registered(d)
            state, _by, detail = host_probes.probe_kimi_shell_surface(
                "kimi", registration_dir=d, version="0.42")
        self.assertEqual(hosts.PROVEN, state)
        self.assertIn("accounted for", detail)

    def test_a_generated_config_that_disables_nothing_is_refuted(self):
        # N3: the round-1 check subtracted `disabled_tools(vocabulary)` from a
        # vocabulary it had just subtracted the same union from -- empty by
        # construction, so it could only fire when the derivation itself was
        # monkeypatched. The question is whether the FILE the runner writes
        # covers the vocabulary, so the answer has to come out of that file.
        import scripts.runners.kimi as kimi_runner
        real = kimi_runner.build_merged_config

        def disables_nothing(source, scope_path, allowlist_path, *args, **kwargs):
            merged = real(source, scope_path, allowlist_path, *args, **kwargs)
            merged["tools"] = {"disabled": []}
            return merged
        with tempfile.TemporaryDirectory() as d:
            _kimi_fully_registered(d)
            with mock.patch.object(kimi_runner, "build_merged_config",
                                   side_effect=disables_nothing):
                state, _by, detail = host_probes.probe_kimi_shell_surface(
                    "kimi", registration_dir=d, version="0.42")
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("FetchURL", detail)

    def test_a_tool_that_is_neither_granted_nor_disabled_is_refuted(self):
        import scripts.runners.kimi as kimi_runner
        with tempfile.TemporaryDirectory() as d:
            _kimi_fully_registered(d)
            with mock.patch.object(kimi_runner, "disabled_tools",
                                   side_effect=lambda vocabulary=None: ["Bash"]):
                state, _by, detail = host_probes.probe_kimi_shell_surface(
                    "kimi", registration_dir=d, version="0.42")
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("FetchURL", detail)


class TestKimiShellSurfaceReadsTheWire(unittest.TestCase):
    """I5: `tool_policy_enforced` rested on configuration text plus a frozen
    belief about the CLI. The runner already owns per-run wire files, so when
    one exists the probe compares the child's own `llm.tools_snapshot` -- the
    EFFECTIVE surface -- against that entry's shell grant. N2: the home comes
    from the live runner in process, never from a path recorded in the tree."""

    def _home(self, snapshot=None, agent="panopticon-domain-panel"):
        """A per-run home holding one child's wire file, as the runner's own
        `run_home` would be. Returns its path."""
        import scripts.runners.kimi as kimi_runner
        home = tempfile.mkdtemp(prefix=kimi_runner.HOME_PREFIX)
        self.addCleanup(shutil.rmtree, home, True)
        if snapshot is not None:
            wire = os.path.join(home, "sessions", "wd_1", "session_x",
                                "agents", "main", "wire.jsonl")
            os.makedirs(os.path.dirname(wire))
            with open(wire, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"type": "llm.request", "modelAlias": "k3"}) + "\n")
                fh.write(json.dumps({"type": "llm.tools_snapshot", "agent": agent,
                                     "tools": list(snapshot)}) + "\n")
        return home

    def test_a_snapshot_matching_the_shells_grant_is_proven_and_says_so(self):
        with tempfile.TemporaryDirectory() as d:
            _kimi_fully_registered(d)
            state, _by, detail = host_probes.probe_kimi_shell_surface(
                "kimi", registration_dir=d, version="0.42",
                run_home=self._home(snapshot=["Read", "Grep", "Glob", "Write"]))
        self.assertEqual(hosts.PROVEN, state)
        self.assertIn("tools_snapshot", detail)
        self.assertIn("panopticon-domain-panel", detail)

    def test_a_snapshot_wider_than_the_grant_is_refuted_naming_both_sets(self):
        with tempfile.TemporaryDirectory() as d:
            _kimi_fully_registered(d)
            state, _by, detail = host_probes.probe_kimi_shell_surface(
                "kimi", registration_dir=d, version="0.42",
                run_home=self._home(snapshot=["Read", "Grep", "Glob", "Write", "Bash"]))
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("Bash", detail)
        self.assertIn("panopticon-domain-panel", detail)

    def test_no_wire_file_yet_falls_back_to_the_table_and_says_so(self):
        with tempfile.TemporaryDirectory() as d:
            _kimi_fully_registered(d)
            state, _by, detail = host_probes.probe_kimi_shell_surface(
                "kimi", registration_dir=d, version="0.42", run_home=self._home())
        self.assertEqual(hosts.PROVEN, state)
        self.assertIn("no child wire file", detail)
        self.assertIn("rests on the version table", detail)

    def test_no_run_home_at_all_falls_back_rather_than_looking_for_one(self):
        with tempfile.TemporaryDirectory() as d:
            _kimi_fully_registered(d)
            state, _by, detail = host_probes.probe_kimi_shell_surface(
                "kimi", registration_dir=d, version="0.42")
        self.assertEqual(hosts.PROVEN, state)
        self.assertIn("no per-run kimi home yet", detail)

    def test_a_planted_pointer_and_wire_file_in_the_tree_are_never_read(self):
        # N2, the forged-evidence half. A target that plants both a pointer
        # file in the run folder and the directory it names cannot make this
        # probe report an effective surface: there is no code path from a file
        # in the reviewed tree to `run_home`.
        import scripts.runners.kimi as kimi_runner
        planted = self._home(snapshot=["Bash", "FetchURL"])
        with tempfile.TemporaryDirectory() as d:
            registration = os.path.join(d, "agents")
            _kimi_fully_registered(registration)
            run_dir = os.path.join(d, "run")
            os.makedirs(run_dir)
            with open(os.path.join(run_dir, kimi_runner.POINTER_FILE), "w",
                      encoding="utf-8") as fh:
                fh.write(planted)
            state, _by, detail = host_probes.probe_kimi_shell_surface(
                "kimi", registration_dir=registration, version="0.42")
        self.assertEqual(hosts.PROVEN, state)
        self.assertNotIn("Bash", detail)
        self.assertNotIn("tools_snapshot for", detail)
