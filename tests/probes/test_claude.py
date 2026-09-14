"""The claude family's probes: `scripts.probes.claude` (#1627 split these out
of tests/test_host_probes.py; the tests themselves are unchanged)."""
import contextlib
import json
import os
import tempfile
import unittest
from unittest import mock

from scripts import dispatch, host_probes, hosts, model_resolver, write_guard_hook
import scripts.probes.claude as claude_probes
import scripts.probes.codex as codex_probes
import scripts.probes.common as probes_common
import scripts.probes.kimi as kimi_probes


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
            state, by, detail = claude_probes.probe_entry_model_bound("claude", d)
        self.assertEqual((hosts.PROVEN, claude_probes.ENTRY_MODEL_BOUND), (state, by))
        self.assertIn("%d/%d" % (len(dispatch.ROLE_FILES), len(dispatch.ROLE_FILES)), detail)

    def test_an_ambient_override_the_shell_cannot_see_is_refuted(self):
        # THE case the probe exists for: resolve_model honours
        # PANOPTICON_MODEL_*, registration_model does not (by design), so the
        # entry requests one model and the enforced shell runs another.
        with tempfile.TemporaryDirectory() as d:
            self._register_all(d)
            with mock.patch.dict(os.environ, {"PANOPTICON_MODEL_DOMAIN_PANEL": "OVERRIDE-X"}):
                state, by, detail = claude_probes.probe_entry_model_bound("claude", d)
        self.assertEqual((hosts.REFUTED, claude_probes.ENTRY_MODEL_BOUND), (state, by))
        self.assertIn("domain_panel", detail)
        self.assertIn("OVERRIDE-X", detail)

    def test_a_shell_that_binds_no_model_is_refuted_not_unknown(self):
        # No `model:` line means the host inherits the SESSION's model for that
        # role -- which silently overrides whatever the entry requested. That
        # is measured, not unmeasured: refuted.
        with tempfile.TemporaryDirectory() as d:
            self._register_all(d)
            _model_shell(d, "claude", "domain-advisor.md", model=None)
            state, _by, detail = claude_probes.probe_entry_model_bound("claude", d)
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
            state, _by, detail = claude_probes.probe_entry_model_bound("claude", d)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("domain_advisor", detail)

    def test_no_registered_shell_is_unknown_never_vacuously_proven(self):
        with tempfile.TemporaryDirectory() as d:
            state, by, _detail = claude_probes.probe_entry_model_bound("claude", d)
        self.assertEqual((hosts.UNKNOWN, claude_probes.ENTRY_MODEL_BOUND), (state, by))

    def test_a_missing_registration_directory_is_unknown(self):
        nonexistent = os.path.join(tempfile.gettempdir(), "no-such-dir-%d" % os.getpid())
        state, _by, _detail = claude_probes.probe_entry_model_bound("claude", nonexistent)
        self.assertEqual(hosts.UNKNOWN, state)

    def test_a_partially_registered_host_is_proven_on_what_is_registered(self):
        # An unregistered role dispatches general-purpose and carries its model
        # on the entry itself (docs/PANOPTICON.md), so it cannot be silently
        # overridden by registration -- there is none. It is named, not hidden.
        with tempfile.TemporaryDirectory() as d:
            _model_shell(d, "claude", "domain-panel.md",
                         model_resolver.resolve_model("claude", "domain_panel")["model"])
            state, _by, detail = claude_probes.probe_entry_model_bound("claude", d)
        self.assertEqual(hosts.PROVEN, state)
        self.assertIn("1/%d" % len(dispatch.ROLE_FILES), detail)
        self.assertIn("scout", detail)          # the absent ones are listed

    def test_a_host_without_shells_is_unknown(self):
        state, by, _detail = claude_probes.probe_entry_model_bound("gemini")
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
                state, _by, detail = claude_probes.probe_entry_model_bound("claude", d)
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("SENTINEL", detail)

    def test_the_registry_names_this_probe_for_claude(self):
        self.assertEqual(claude_probes.ENTRY_MODEL_BOUND,
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
        self.assertEqual(claude_probes.ENTRY_MODEL_BOUND, row["by"])
        self.assertIn(row["state"], (hosts.PROVEN, hosts.REFUTED))   # measured, not unknown

    def test_a_freshly_emitted_registration_proves(self):
        # The probe parses a format dispatch.emit_host_agents writes. Every
        # other fixture here hand-writes shells; this one uses the real
        # emitter so a change to the emitted frontmatter (quoting, indent,
        # key order) cannot silently flip a correct machine to REFUTED.
        with tempfile.TemporaryDirectory() as d:
            dispatch.emit_host_agents("claude", d)
            state, _by, _detail = claude_probes.probe_entry_model_bound("claude", d)
        self.assertEqual(hosts.PROVEN, state)

    def test_probe_ids_name_exactly_the_shipped_runners(self):
        # The retirement bar (tests/test_generic_retirement_bar.py) reads
        # PROBE_IDS as "the shipped probes" (spec 8.1). A runner that exists
        # but is not listed would make the bar stricter than reality; a listed
        # id with no runner would make it vacuous. run_probes refuses to build
        # a table that disagrees, so the constant cannot rot in either direction.
        self.assertEqual(sorted(host_probes.PROBE_IDS),
                         sorted({probes_common.REGISTERED_SHELL_TOOLS,
                                 claude_probes.WRITE_GUARD_ARMED,
                                 claude_probes.USAGE_SOURCE,
                                 claude_probes.ENTRY_MODEL_BOUND,
                                 claude_probes.READ_GUARD_ARMED,
                                 # #1344 codex family PR (#1619): the two
                                 # probes the codex row maps its claims to.
                                 codex_probes.CODEX_EFFECTIVE_TOOLS,
                                 codex_probes.CODEX_READ_SCOPE,
                                 # #1344 kimi family PR (#1620): the five
                                 # probes the kimi row maps its five claims to.
                                 kimi_probes.KIMI_SHELL_SURFACE,
                                 kimi_probes.KIMI_READ_GUARD,
                                 kimi_probes.KIMI_WRITE_GUARD,
                                 kimi_probes.KIMI_MODEL_ALIAS,
                                 kimi_probes.KIMI_USAGE_WIRE}))
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
            state, by, detail = claude_probes.probe_write_guard_armed(
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
            state, _by, _detail = claude_probes.probe_write_guard_armed(
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
            state, _by, detail = claude_probes.probe_write_guard_armed(
                "claude", session_root=session_root)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn("settings.local.json", detail)

    def test_an_unwritable_settings_root_is_refuted(self):
        # THE negative fixture: the host cannot arm what it cannot write.
        with tempfile.TemporaryDirectory() as session_root:
            claude_dir = self._session_root(session_root)
            os.chmod(claude_dir, 0o500)          # r-x: no writes
            try:
                state, _by, detail = claude_probes.probe_write_guard_armed(
                    "claude", session_root=session_root)
            finally:
                os.chmod(claude_dir, 0o700)      # restore so cleanup succeeds
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn(claude_dir, detail)

    def test_a_host_that_claims_no_write_guard_is_unknown(self):
        for name in ("gemini", "generic"):
            with self.subTest(host=name):
                state, by, _detail = claude_probes.probe_write_guard_armed(name)
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
            state, _by, _detail = claude_probes.probe_write_guard_armed(
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
            state, _by, detail = claude_probes.probe_write_guard_armed(
                "claude", session_root=session_root)
            self.assertEqual(hosts.PROVEN, state)
            self.assertIn(resolved, detail)
            os.remove(resolved)
            state, _by, detail = claude_probes.probe_write_guard_armed(
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
            state, _by, detail = claude_probes.probe_write_guard_armed("claude")
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn(os.path.abspath(resolved), detail)
            os.makedirs(os.path.dirname(resolved), exist_ok=True)
            with open(resolved, "w", encoding="utf-8") as fh:
                fh.write("{}")
            state, _by, _detail = claude_probes.probe_write_guard_armed("claude")
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
                claude_probes.probe_write_guard_armed("claude")[0],
                claude_probes.probe_write_guard_armed(
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
            with mock.patch.object(claude_probes.tempfile, "TemporaryDirectory",
                                   side_effect=OSError("no space left")):
                state, by, detail = claude_probes.probe_write_guard_armed(
                    "claude", session_root=session_root)
        self.assertEqual(hosts.REFUTED, state)
        self.assertEqual(claude_probes.WRITE_GUARD_ARMED, by)
        self.assertIn("no space left", detail)

    def test_an_explicit_settings_path_is_the_subject_and_need_not_exist_yet(self):
        # Spec 5.4 / R-P6-5: in headless mode the runner CREATES the settings
        # file after the first probe, so the probe must not demand it exists;
        # it demands the directory can be written. Same verdict before and
        # after the file appears, or posture drift would refuse iteration 2.
        with tempfile.TemporaryDirectory() as run_dir:
            path = os.path.join(run_dir, "host-settings.json")
            state1, by, detail1 = claude_probes.probe_write_guard_armed("claude", settings_path=path)
            self.assertEqual(hosts.PROVEN, state1)
            self.assertIn(path, detail1)
            with open(path, "w") as fh:
                fh.write("{}")
            state2, _by, _d = claude_probes.probe_write_guard_armed("claude", settings_path=path)
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
                state, _by, detail = claude_probes.probe_write_guard_armed(
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
        real_resolve = claude_probes.write_guard_hook._resolve
        def fallback_only(settings_path, allowlist_path, session_root):
            if settings_path is None and allowlist_path is None:
                raise AssertionError(
                    "must not fall back to _resolve when settings_path is given")
            return real_resolve(settings_path, allowlist_path, session_root)
        with tempfile.TemporaryDirectory() as run_dir:
            with mock.patch.object(claude_probes.write_guard_hook, "_resolve",
                                   side_effect=fallback_only):
                state, _by, _d = claude_probes.probe_write_guard_armed(
                    "claude", settings_path=os.path.join(run_dir, "host-settings.json"))
            self.assertEqual(hosts.PROVEN, state)


class TestUsageSourceProbe(unittest.TestCase):
    """#1344 F3a, reworked by the Claude family PR: usage_ledger is
    operational, not security (8.1 excludes it from F5's bar), but an unprobed
    capability must still say so -- and the probe follows the MODE (spec 5.4's
    rule applied to usage, spec 5.5). Session mode's figures come from the
    host's own transcripts, so the session's transcript directory is the
    subject. Headless mode's come from the JSON envelope of every `claude -p`
    launch, ledgered into the run folder by the loop, so the CLI on PATH and a
    run folder that can hold the ledger are the subject and transcripts are
    never consulted: a fresh target directory has no transcripts and used to
    REFUTE a headless run whose ledger was exact."""

    def _transcripts(self, home, project_dir):
        from scripts import collect_usage
        d = os.path.join(home, ".claude", "projects",
                         collect_usage.project_slug(project_dir))
        os.makedirs(d, exist_ok=True)
        return d

    def _cli_on_path(self, bin_dir, name="claude"):
        """An executable file for shutil.which to find. Never run: every
        launch in the suite goes through the runner's launcher, which
        tests/conftest.py refuses unless a test injects a fake (`_help`)."""
        os.makedirs(bin_dir, exist_ok=True)
        path = os.path.join(bin_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\nexit 0\n")
        os.chmod(path, 0o755)
        return path

    def _help(self, text=None, returncode=0):
        """Patch the runner's default launcher with a fake `claude --help`
        that prints `text` (the intact shape advertises the runner's own
        envelope flags) and exits `returncode`."""
        import subprocess
        import scripts.runners.claude as claude_runner
        if text is None:
            text = "Usage: claude [options]\n  -p, --print   Print\n  --output-format <format>\n"
        self.help_calls = []

        def fake(cmd, **kwargs):
            self.help_calls.append(list(cmd))
            return subprocess.CompletedProcess(cmd, returncode, stdout=text, stderr="")
        return mock.patch.object(claude_runner, "DEFAULT_RUNNER", fake)

    def _headless_settings(self, project):
        return os.path.join(project, ".panopticon", "runs", "tag", "host-settings.json")

    def _ledger(self, settings, rows):
        import scripts.runners.base as runners_base
        path = os.path.join(os.path.dirname(settings), runners_base.LEDGER_FILE)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")
        return path

    # -- session mode: the transcript directory is the subject ---------------

    def test_a_readable_transcript_dir_is_proven(self):
        with tempfile.TemporaryDirectory() as home, \
                tempfile.TemporaryDirectory() as project:
            d = self._transcripts(home, project)
            state, by, detail = claude_probes.probe_usage_source(
                "claude", project, home=home)
            self.assertEqual(hosts.PROVEN, state)
            self.assertEqual("usage-source", by)
            self.assertIn(d, detail)

    def test_an_absent_transcript_dir_is_refuted(self):
        # THE session-mode negative fixture. A host that claims a usage ledger
        # and has no transcripts cannot produce one.
        with tempfile.TemporaryDirectory() as home, \
                tempfile.TemporaryDirectory() as project:
            state, _by, detail = claude_probes.probe_usage_source(
                "claude", project, home=home)
            self.assertEqual(hosts.REFUTED, state)
            self.assertEqual("usage-source", _by)
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
                state, by, detail = claude_probes.probe_usage_source(
                    "claude", project, home=home)
            finally:
                os.chmod(d, 0o700)
            self.assertEqual(hosts.REFUTED, state)
            self.assertEqual("usage-source", by)
            self.assertIn(d, detail)

    def test_a_host_that_claims_no_usage_ledger_is_unknown(self):
        for name in ("gemini", "generic", "codex"):
            with self.subTest(host=name):
                state, by, _detail = claude_probes.probe_usage_source(name, ".")
                self.assertEqual(hosts.UNKNOWN, state)
                self.assertIsNone(by)

    def test_the_usage_probe_id_matches_the_registry_row(self):
        self.assertEqual(claude_probes.USAGE_SOURCE,
                         hosts.spec("claude").probes[hosts.USAGE_LEDGER])

    # -- headless mode: the envelope and the ledger are the subject ----------

    def test_headless_proves_the_envelope_path_and_never_consults_transcripts(self):
        # `home` holds NO transcripts at all, and the probe must not care: the
        # headless figures never come from there. The detail names the surface
        # it did inspect -- the CLI it found and the ledger the loop will
        # write -- as spec 2 of the family guardrails requires.
        with tempfile.TemporaryDirectory() as home, \
                tempfile.TemporaryDirectory() as project, \
                tempfile.TemporaryDirectory() as bin_dir:
            cli = self._cli_on_path(bin_dir)
            settings = self._headless_settings(project)
            with mock.patch.dict(os.environ, {"PATH": bin_dir}), self._help():
                state, by, detail = claude_probes.probe_usage_source(
                    "claude", project, home=home, settings_path=settings)
            self.assertEqual(hosts.PROVEN, state)
            self.assertEqual("usage-source", by)
            self.assertIn(cli, detail)
            self.assertIn(os.path.join(os.path.dirname(settings), "dispatch-ledger.jsonl"), detail)
            self.assertIn("advertises -p, --output-format", detail)
            self.assertIn("every successful launch ledgered there carrying its figure", detail)
            self.assertNotIn("transcript directory", detail)
            self.assertFalse(os.path.isdir(os.path.join(home, ".claude")))
            # The interrogation is `<found cli> --help`, through the launcher.
            self.assertEqual([[cli, "--help"]], self.help_calls)

    def test_headless_refutes_when_no_cli_is_on_path(self):
        # THE headless negative fixture. Transcripts present, CLI absent: the
        # runner cannot launch, so no envelope will ever carry usage -- and the
        # session-mode evidence must not rescue it.
        with tempfile.TemporaryDirectory() as home, \
                tempfile.TemporaryDirectory() as project, \
                tempfile.TemporaryDirectory() as empty_bin:
            self._transcripts(home, project)
            settings = self._headless_settings(project)
            with mock.patch.dict(os.environ, {"PATH": empty_bin}):
                state, by, detail = claude_probes.probe_usage_source(
                    "claude", project, home=home, settings_path=settings)
            self.assertEqual(hosts.REFUTED, state)
            self.assertEqual("usage-source", by)
            self.assertIn("claude", detail)
            self.assertIn("PATH", detail)

    def test_headless_refutes_a_cli_that_does_not_advertise_the_envelope_flags(self):
        # Review of this branch: existence alone let any executable named
        # `claude` prove the ledger. The probe now drives `<cli> --help` and
        # requires the runner's own ENVELOPE_FLAGS; a CLI advertising neither,
        # or exiting non-zero, is refuted and the missing flags are named.
        with tempfile.TemporaryDirectory() as project, \
                tempfile.TemporaryDirectory() as bin_dir:
            settings = self._headless_settings(project)
            self._cli_on_path(bin_dir)
            with mock.patch.dict(os.environ, {"PATH": bin_dir}), \
                    self._help("usage: something-else [--verbose] [--print]"):
                state, by, detail = claude_probes.probe_usage_source(
                    "claude", project, settings_path=settings)
            self.assertEqual(hosts.REFUTED, state)
            self.assertEqual("usage-source", by)
            self.assertIn("does not advertise -p, --output-format", detail)   # --print is not -p
            with mock.patch.dict(os.environ, {"PATH": bin_dir}), self._help(returncode=3):
                state, _by, detail = claude_probes.probe_usage_source(
                    "claude", project, settings_path=settings)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn("exited 3", detail)

    def test_headless_refutes_a_ledger_whose_successful_launches_carried_no_usage(self):
        # The evidence surface the probe names is read back on every
        # re-probe: successful launches whose envelopes carried no figure at
        # all refute the ledger on what was measured (a re-probe after batch
        # one, so the mid-run posture check sees it), while a single odd row
        # among launches that did carry usage does not.
        with tempfile.TemporaryDirectory() as project, \
                tempfile.TemporaryDirectory() as bin_dir:
            settings = self._headless_settings(project)
            self._cli_on_path(bin_dir)
            empty = {"ok": True, "usage": {}}
            counted = {"ok": True, "usage": {"input_tokens": 12, "output_tokens": 3}}
            failed = {"ok": False, "usage": {}, "error": "timed out"}
            self._ledger(settings, [empty, empty, failed])
            with mock.patch.dict(os.environ, {"PATH": bin_dir}), self._help():
                state, by, detail = claude_probes.probe_usage_source(
                    "claude", project, settings_path=settings)
            self.assertEqual(hosts.REFUTED, state)
            self.assertEqual("usage-source", by)
            self.assertIn("2 successful launch(es)", detail)
            self.assertIn("not one envelope carried a usage figure", detail)
            self._ledger(settings, [empty, counted, failed])
            with mock.patch.dict(os.environ, {"PATH": bin_dir}), self._help():
                state, _by, _detail = claude_probes.probe_usage_source(
                    "claude", project, settings_path=settings)
            self.assertEqual(hosts.PROVEN, state)
            self._ledger(settings, [failed])                 # nothing succeeded yet: no verdict
            with mock.patch.dict(os.environ, {"PATH": bin_dir}), self._help():
                state, _by, _detail = claude_probes.probe_usage_source(
                    "claude", project, settings_path=settings)
            self.assertEqual(hosts.PROVEN, state)

    def test_the_proven_detail_is_the_same_before_and_after_launches(self):
        # driver._establish_host_posture rewrites host-capabilities.json
        # whenever a detail changes (a stale reason is a wrong disclosure),
        # and its comment names "always write on every turn of the loop" as
        # the hazard that rule must not become. A running launch count in the
        # proven detail was exactly that: measured on a real run, `probed_at`
        # moved to the last iteration. The proven detail is one string for
        # the whole run; only the refutation carries numbers.
        with tempfile.TemporaryDirectory() as project, \
                tempfile.TemporaryDirectory() as bin_dir:
            settings = self._headless_settings(project)
            self._cli_on_path(bin_dir)
            with mock.patch.dict(os.environ, {"PATH": bin_dir}), self._help():
                before = claude_probes.probe_usage_source("claude", project, settings_path=settings)
            self._ledger(settings, [{"ok": True, "usage": {"input_tokens": 12, "output_tokens": 3}},
                                    {"ok": False, "usage": {}, "error": "timed out"}])
            with mock.patch.dict(os.environ, {"PATH": bin_dir}), self._help():
                after_one = claude_probes.probe_usage_source("claude", project, settings_path=settings)
            self._ledger(settings, [{"ok": True, "usage": {"input_tokens": 1}} for _ in range(15)])
            with mock.patch.dict(os.environ, {"PATH": bin_dir}), self._help():
                after_many = claude_probes.probe_usage_source("claude", project, settings_path=settings)
        self.assertEqual(hosts.PROVEN, before[0])
        self.assertEqual(before, after_one)
        self.assertEqual(before, after_many)

    def test_headless_is_unknown_when_the_cli_cannot_even_print_help(self):
        # Could not measure is not "measured and broken": a `--help` the
        # launcher cannot complete (here: a timeout) is UNKNOWN with the reason.
        import subprocess
        import scripts.runners.claude as claude_runner

        def hangs(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))
        with tempfile.TemporaryDirectory() as project, \
                tempfile.TemporaryDirectory() as bin_dir:
            self._cli_on_path(bin_dir)
            with mock.patch.dict(os.environ, {"PATH": bin_dir}), \
                    mock.patch.object(claude_runner, "DEFAULT_RUNNER", hangs):
                state, by, detail = claude_probes.probe_usage_source(
                    "claude", project, settings_path=self._headless_settings(project))
            self.assertEqual(hosts.UNKNOWN, state)
            self.assertEqual("usage-source", by)
            self.assertIn("could not run", detail)

    def test_the_interrogation_goes_through_the_launcher_the_suite_refuses(self):
        # The seam, proved from the suite's side: with no fake injected, the
        # probe's `--help` reaches tests/conftest.py's refusal and fails
        # loudly, instead of running whatever `claude` is on PATH. A forgotten
        # fake is a failed test, never a real launch.
        with tempfile.TemporaryDirectory() as project, \
                tempfile.TemporaryDirectory() as bin_dir:
            self._cli_on_path(bin_dir)
            with mock.patch.dict(os.environ, {"PATH": bin_dir}), \
                    self.assertRaisesRegex(RuntimeError, "never launch the real `claude` binary"):
                claude_probes.probe_usage_source(
                    "claude", project, settings_path=self._headless_settings(project))

    def test_a_flag_is_advertised_only_as_a_standalone_token(self):
        self.assertTrue(probes_common._flag_advertised("-p", "  -p, --print   Print response"))
        self.assertTrue(probes_common._flag_advertised("--output-format", "--output-format=stream-json"))
        self.assertFalse(probes_common._flag_advertised("-p", "  --print   Print response"))
        self.assertFalse(probes_common._flag_advertised("-p", "  --permission-mode <mode>"))
        self.assertFalse(probes_common._flag_advertised("--output-format", "--output-formats"))

    def test_headless_is_unknown_on_a_claiming_host_whose_runner_module_is_broken(self):
        # A probe reports, never raises: a runners/<host>.py that exists but
        # fails to import (base._headless_module re-raises that on purpose)
        # is the family's bug, reported as UNKNOWN naming the exception
        # rather than as a traceback out of driver.run.
        import dataclasses
        import scripts.runners.base as runners_base
        ghost = dataclasses.replace(hosts.spec("claude"), name="ghost")
        with tempfile.TemporaryDirectory() as project, \
                mock.patch.dict(hosts.HOSTS, {"ghost": ghost}), \
                mock.patch.object(runners_base, "runner_for",
                                  side_effect=ImportError("runners/ghost.py: no module named yaml")):
            state, by, detail = claude_probes.probe_usage_source(
                "ghost", project, settings_path=self._headless_settings(project))
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertEqual("usage-source", by)
        self.assertIn("ImportError", detail)
        self.assertIn("no usable headless runner", detail)

    def test_a_runner_with_no_envelope_flags_is_told_that_and_not_sent_module_hunting(self):
        # #1626 I3. `_headless_usage_source` requires three attributes off the
        # runner, `HostRunner` declared none of them, and the ONE failure
        # detail read "host %r has no usable headless runner naming a CLI, its
        # envelope flags and a launcher" -- wrong and misleading for a family
        # that shipped a perfectly good runner and simply has no
        # ENVELOPE_FLAGS. The remedy line then sent them looking for a missing
        # module. Now `HostRunner` declares `CLI = ""` and `ENVELOPE_FLAGS =
        # ()`, so the attribute is always there and the probe has to decide on
        # its VALUE -- a vacuous PROVEN (no flags means no flags missing from
        # `--help`) is the fail-open this epic exists to remove.
        import dataclasses
        import scripts.runners.base as runners_base

        class NoFlags(runners_base.HostRunner):
            host = "ghost"
            CLI = "claude"

            def runner(self, *_args, **_kwargs):
                raise AssertionError("a runner with no envelope flags is never launched")

        ghost = dataclasses.replace(hosts.spec("claude"), name="ghost")
        with tempfile.TemporaryDirectory() as project, \
                tempfile.TemporaryDirectory() as bin_dir, \
                mock.patch.dict(hosts.HOSTS, {"ghost": ghost}), \
                mock.patch.object(runners_base, "runner_for", return_value=NoFlags()):
            self._cli_on_path(bin_dir)
            with mock.patch.dict(os.environ, {"PATH": bin_dir}):
                state, by, detail = claude_probes.probe_usage_source(
                    "ghost", project, settings_path=self._headless_settings(project))
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertEqual("usage-source", by)
        self.assertIn("ENVELOPE_FLAGS", detail)
        self.assertIn("claude", detail)                       # the CLI it DID name
        self.assertNotIn("no usable headless runner", detail)  # the wrong sentence

    def test_a_runner_that_names_no_cli_is_told_that_and_not_that_its_binary_is_missing(self):
        # The third sentence. `CLI = ""` reached `shutil.which("")`, which
        # answers None, and the probe REFUTED with "no `` on PATH" -- a
        # measurement it never made, about a binary nobody named.
        import dataclasses
        import scripts.runners.base as runners_base

        class NoCli(runners_base.HostRunner):
            host = "ghost"
            ENVELOPE_FLAGS = ("-p", "--output-format")

            def runner(self, *_args, **_kwargs):
                raise AssertionError("a runner that names no CLI is never launched")

        ghost = dataclasses.replace(hosts.spec("claude"), name="ghost")
        with tempfile.TemporaryDirectory() as project, \
                mock.patch.dict(hosts.HOSTS, {"ghost": ghost}), \
                mock.patch.object(runners_base, "runner_for", return_value=NoCli()):
            state, by, detail = claude_probes.probe_usage_source(
                "ghost", project, settings_path=self._headless_settings(project))
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertEqual("usage-source", by)
        self.assertIn("names no CLI", detail)
        # Not the pre-fix sentence, which reported a measurement it never
        # made about a binary nobody named. (The new one may still mention
        # PATH -- "there is no binary to look for on PATH" is true and is the
        # point -- so the empty backticks, not the word, are what it must not
        # say.)
        self.assertNotIn("no `` on PATH", detail)
        self.assertNotIn("no usable headless runner", detail)

    def test_headless_refutes_when_the_run_folder_cannot_hold_the_ledger(self):
        import getpass
        if getpass.getuser() == "root":
            self.skipTest("running as root, os.access ignores permissions")
        with tempfile.TemporaryDirectory() as project, \
                tempfile.TemporaryDirectory() as bin_dir:
            self._cli_on_path(bin_dir)
            pano = os.path.join(project, ".panopticon")
            os.makedirs(pano)
            os.chmod(pano, 0o500)
            try:
                with mock.patch.dict(os.environ, {"PATH": bin_dir}):
                    state, by, detail = claude_probes.probe_usage_source(
                        "claude", project, settings_path=self._headless_settings(project))
            finally:
                os.chmod(pano, 0o700)
            self.assertEqual(hosts.REFUTED, state)
            self.assertEqual("usage-source", by)
            self.assertIn("ledger", detail)
            self.assertIn("not writable", detail)

    def test_a_launcher_that_raises_anything_at_all_is_unknown_not_a_traceback(self):
        # #1626 I2. `launch` is a FAMILY-supplied callable (`Runner.runner`).
        # The clause here caught (OSError, SubprocessError, ValueError) while
        # the sibling block ten lines below deliberately catches bare
        # `Exception` with "a probe reports, never raises" -- so a runner with
        # a different signature (TypeError) or one that refuses with a plain
        # RuntimeError escaped run_probes -> _establish_host_posture ->
        # driver.run, which does not wrap it: a `driver run` printed a
        # traceback instead of a status. The three family PRs are exactly the
        # population that hits this.
        import subprocess as _subprocess
        import scripts.runners.claude as claude_runner
        cases = [TypeError("runner() takes 2 positional arguments but 4 were given"),
                 RuntimeError("this family's launcher refuses"),
                 _subprocess.SubprocessError("still caught, as before")]
        for exc in cases:
            with self.subTest(exception=type(exc).__name__):
                def raises(cmd, _exc=exc, **kwargs):
                    raise _exc
                with tempfile.TemporaryDirectory() as project, \
                        tempfile.TemporaryDirectory() as bin_dir:
                    self._cli_on_path(bin_dir)
                    with mock.patch.dict(os.environ, {"PATH": bin_dir}), \
                            mock.patch.object(claude_runner, "DEFAULT_RUNNER", raises):
                        state, by, detail = claude_probes.probe_usage_source(
                            "claude", project,
                            settings_path=self._headless_settings(project))
                self.assertEqual(hosts.UNKNOWN, state)
                self.assertEqual("usage-source", by)
                self.assertIn("could not run", detail)
                # The detail names the exception TYPE as well as its text: a
                # bare str(TypeError) reads like prose and tells a family
                # nothing about where to look.
                self.assertIn(type(exc).__name__, detail)

    def test_the_interrogation_runs_under_the_runners_own_env_discipline(self):
        # #1626 I2, the second half. `Runner.run_entry` pops CLAUDECODE
        # because a nested `claude -p` refuses to start inside a Claude Code
        # session; the probe launched the same binary with the caller's
        # environment untouched, so it interrogated the CLI under an
        # environment the runner never uses. It works today only because
        # `--help` is handled at argparse level -- the day that refusal moves
        # earlier in start-up, every self-scan run from inside a session
        # refutes usage_ledger.
        import subprocess as _subprocess
        import scripts.runners.claude as claude_runner
        seen = {}

        def fake(cmd, **kwargs):
            seen.update(kwargs)
            return _subprocess.CompletedProcess(
                cmd, 0, stdout="  -p, --print\n  --output-format <format>\n", stderr="")
        with tempfile.TemporaryDirectory() as project, \
                tempfile.TemporaryDirectory() as bin_dir:
            self._cli_on_path(bin_dir)
            with mock.patch.dict(os.environ, {"PATH": bin_dir, "CLAUDECODE": "1"}), \
                    mock.patch.object(claude_runner, "DEFAULT_RUNNER", fake):
                state, _by, _detail = claude_probes.probe_usage_source(
                    "claude", project, settings_path=self._headless_settings(project))
        self.assertEqual(hosts.PROVEN, state)
        env = seen.get("env")
        self.assertIsInstance(env, dict)
        self.assertNotIn("CLAUDECODE", env)
        # ...and it is a whole ENVIRONMENT, not a filtered overlay: a child
        # handed only the keys the runner cares about has no PATH and cannot
        # start, which is the C1 defect run_entry already carries a comment
        # about. One preparation, so the probe cannot regrow that bug.
        self.assertEqual(bin_dir, env.get("PATH"))

    def test_headless_is_unknown_on_a_claiming_host_with_no_headless_runner(self):
        # A row that claims the ledger but ships no runners/<host>.py has no
        # CLI to look for: nothing here can prove an envelope, and a vacuous
        # PROVEN is the fail-open this epic exists to remove.
        import dataclasses
        ghost = dataclasses.replace(hosts.spec("claude"), name="ghost")
        with tempfile.TemporaryDirectory() as project, \
                mock.patch.dict(hosts.HOSTS, {"ghost": ghost}):
            state, by, detail = claude_probes.probe_usage_source(
                "ghost", project, settings_path=self._headless_settings(project))
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertEqual("usage-source", by)
        self.assertIn("no usable headless runner", detail)


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
            state, by, detail = claude_probes.probe_read_guard_armed("claude", session_root=session_root)
            self.assertEqual(hosts.PROVEN, state)
            self.assertEqual("read-guard-armed", by)
            self.assertIn(session_root, detail)
            self.assertIn("16 rows", detail)

    def test_it_does_not_require_the_guard_to_be_armed_right_now(self):
        from scripts import read_guard_hook
        with tempfile.TemporaryDirectory() as session_root:
            self._session_root(session_root)
            self.assertFalse(read_guard_hook.guard_state(session_root=session_root)["armed"])
            state, _by, _detail = claude_probes.probe_read_guard_armed("claude", session_root=session_root)
            self.assertEqual(hosts.PROVEN, state)

    def test_a_missing_settings_file_is_refuted(self):
        with tempfile.TemporaryDirectory() as session_root:
            os.makedirs(os.path.join(session_root, ".claude"), exist_ok=True)
            state, _by, detail = claude_probes.probe_read_guard_armed("claude", session_root=session_root)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn("settings.local.json", detail)

    def test_an_unwritable_settings_root_is_refuted(self):
        with tempfile.TemporaryDirectory() as session_root:
            claude_dir = self._session_root(session_root)
            os.chmod(claude_dir, 0o500)
            try:
                state, _by, detail = claude_probes.probe_read_guard_armed("claude", session_root=session_root)
            finally:
                os.chmod(claude_dir, 0o700)
            self.assertEqual(hosts.REFUTED, state)
            self.assertIn(claude_dir, detail)

    def test_a_host_that_claims_no_read_confinement_is_unknown(self):
        # codex and kimi both left this tuple in their own family PRs (#1619,
        # #1620): each now claims READ_SCOPE_CONFINED and ships its own probe
        # (codex-read-scope, kimi-read-guard-armed), so the claude-shaped probe
        # must never run for either. What is left is every family with no
        # read-confinement claim at all.
        for name in ("gemini", "generic"):
            with self.subTest(host=name):
                state, by, _detail = claude_probes.probe_read_guard_armed(name)
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
                    state, by, detail = claude_probes.probe_read_guard_armed("claude", session_root=session_root)
                    self.assertEqual(hosts.REFUTED, state)
                    self.assertEqual("read-guard-armed", by)
                    self.assertIn("the guard", detail)

    def test_the_probe_leaves_the_sessions_settings_untouched(self):
        with tempfile.TemporaryDirectory() as session_root:
            self._session_root(session_root)
            settings = os.path.join(session_root, ".claude", "settings.local.json")
            claude_probes.probe_read_guard_armed("claude", session_root=session_root)
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
        ok, detail = claude_probes._round_trip_confines_reads()
        self.assertTrue(ok, detail)
        real = read_guard_hook.adjudicate
        def ignores_env(payload, scope_path, env=None):
            return real(payload, scope_path, env={})
        with mock.patch.object(read_guard_hook, "adjudicate", ignores_env):
            ok, detail = claude_probes._round_trip_confines_reads()
        self.assertFalse(ok)
        self.assertIn("env", detail)

    def test_the_round_trip_proves_the_workflow_transcript_layout(self):
        # Claude family PR: the shipped session-mode dispatch workflow
        # (skill/workflows/dispatch.js) runs every entry as a WORKFLOW
        # subagent, whose transcript lands under
        # `<stem>/subagents/workflows/<run>/agent-<id>.jsonl` rather than in
        # the Agent-tool layout beside it. The round trip binds one fake
        # subagent through that layout; a guard that only knew the direct
        # layout leaves it unbound (every read denied) and the probe refutes,
        # naming the row.
        from scripts import read_guard_hook
        ok, detail = claude_probes._round_trip_confines_reads()
        self.assertTrue(ok, detail)
        real = read_guard_hook.subagent_transcript

        def direct_layout_only(transcript_path, agent_id):
            found = real(transcript_path, agent_id)
            if found and (os.sep + "workflows" + os.sep) in found:
                return None
            return found
        with mock.patch.object(read_guard_hook, "subagent_transcript", direct_layout_only):
            ok, detail = claude_probes._round_trip_confines_reads()
        self.assertFalse(ok)
        self.assertIn("workflow", detail)

    def test_an_explicit_settings_path_is_the_subject_and_need_not_exist_yet(self):
        # Spec 5.4 / R-P6-5: in headless mode the runner CREATES the settings
        # file after the first probe, so the probe must not demand it exists;
        # it demands the directory can be written. Same verdict before and
        # after the file appears, or posture drift would refuse iteration 2.
        with tempfile.TemporaryDirectory() as run_dir:
            path = os.path.join(run_dir, "host-settings.json")
            state1, by, detail1 = claude_probes.probe_read_guard_armed("claude", settings_path=path)
            self.assertEqual(hosts.PROVEN, state1)
            self.assertIn(path, detail1)
            with open(path, "w") as fh:
                fh.write("{}")
            state2, _by, _d = claude_probes.probe_read_guard_armed("claude", settings_path=path)
            self.assertEqual(state1, state2)

    def test_an_unwritable_headless_directory_refutes(self):
        # try/finally, not addCleanup -- see the write-probe mirror above.
        with tempfile.TemporaryDirectory() as run_dir:
            locked = os.path.join(run_dir, "ro"); os.makedirs(locked); os.chmod(locked, 0o500)
            try:
                if os.access(locked, os.W_OK):
                    self.skipTest("running as a user who can write a 0500 directory")
                state, _by, detail = claude_probes.probe_read_guard_armed(
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
        real_resolve = claude_probes.read_guard_hook._resolve
        def fallback_only(settings_path, allowlist_path, session_root):
            if settings_path is None and allowlist_path is None:
                raise AssertionError(
                    "must not fall back to _resolve when settings_path is given")
            return real_resolve(settings_path, allowlist_path, session_root)
        with tempfile.TemporaryDirectory() as run_dir:
            with mock.patch.object(claude_probes.read_guard_hook, "_resolve",
                                   side_effect=fallback_only):
                state, _by, _d = claude_probes.probe_read_guard_armed(
                    "claude", settings_path=os.path.join(run_dir, "host-settings.json"))
            self.assertEqual(hosts.PROVEN, state)
