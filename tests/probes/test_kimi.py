"""The kimi family's probes: `scripts.probes.kimi` (#1627 split these out of
tests/test_host_probes.py; the tests themselves are unchanged)."""
import inspect
import json
import os
import shlex
import shutil
import tempfile
import unittest
from unittest import mock

from scripts import dispatch, host_probes, hosts
import scripts.probes.common as probes_common
import scripts.probes.kimi as kimi_probes
from tests.probes.helpers import _shell


def _kimi_fully_registered(directory):
    """Register all four driver shells in kimi's block-list dialect, granting
    exactly each template's tool policy (the state --emit-host-agents kimi
    produces)."""
    for role in probes_common.DRIVER_ROLES:
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
            state, by, detail = kimi_probes.probe_kimi_shell_surface(
                "kimi", registration_dir=d, version="0.42")
        self.assertEqual(hosts.PROVEN, state)
        self.assertEqual(kimi_probes.KIMI_SHELL_SURFACE, by)
        self.assertIn("0.42", detail)

    def test_missing_shells_are_refuted_by_the_template_half(self):
        with tempfile.TemporaryDirectory() as d:
            state, by, detail = kimi_probes.probe_kimi_shell_surface(
                "kimi", registration_dir=d, version="0.42")
        self.assertEqual(hosts.REFUTED, state)
        self.assertEqual(kimi_probes.KIMI_SHELL_SURFACE, by)
        self.assertIn("no shell", detail)

    def test_a_shell_grant_the_template_forbids_is_refuted(self):
        with tempfile.TemporaryDirectory() as d:
            _kimi_fully_registered(d)
            _shell(d, dispatch.registered_agent_filename("kimi", "scout.md"),
                   ["Read", "Grep", "Glob", "Bash"], block_list=True)
            state, _by, detail = kimi_probes.probe_kimi_shell_surface(
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
                state, _by, detail = kimi_probes.probe_kimi_shell_surface(
                    "kimi", registration_dir=d, version="0.42")
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("match nothing", detail)

    def test_an_uncovered_cli_version_is_unknown_never_a_guess(self):
        with tempfile.TemporaryDirectory() as d:
            _kimi_fully_registered(d)
            state, _by, detail = kimi_probes.probe_kimi_shell_surface(
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
            state, _by, _detail = kimi_probes.probe_kimi_shell_surface(
                "kimi", registration_dir=d, runner=garbage)
        self.assertEqual(hosts.UNKNOWN, state)

    def test_a_host_that_registers_no_shells_is_unknown(self):
        state, by, _detail = kimi_probes.probe_kimi_shell_surface("gemini", version="0.42")
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIsNone(by)


class TestKimiReadGuardProbe(unittest.TestCase):
    """The kimi read_scope_confined probe: the real guard subprocess round-trip
    (plain python -- not the host binary) plus a faked doctor validation."""

    def test_the_round_trip_and_a_valid_home_are_proven(self):
        state, by, detail = kimi_probes.probe_kimi_read_guard(
            "kimi", doctor_runner=_DoctorFake())
        self.assertEqual(hosts.PROVEN, state)
        self.assertEqual(kimi_probes.KIMI_READ_GUARD, by)
        self.assertIn("round-trip", detail)

    def test_a_doctor_rejection_is_refuted(self):
        state, _by, detail = kimi_probes.probe_kimi_read_guard(
            "kimi", doctor_runner=_DoctorFake(ok=False))
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("doctor", detail)

    def test_a_missing_cli_is_unknown_not_refuted(self):
        def no_binary(cmd, **kw):
            raise FileNotFoundError("kimi")
        state, _by, detail = kimi_probes.probe_kimi_read_guard(
            "kimi", doctor_runner=no_binary)
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIn("could not run", detail)

    def test_a_guard_failure_is_refuted_with_the_row_named(self):
        # The mutation, at the probe's own seam: a guard that allows an
        # outside read must flip the probe to refuted.
        with mock.patch.object(kimi_probes, "_guard_round_trip",
                               return_value=(False, "the guard ALLOWED: bound Read outside scope")):
            state, _by, detail = kimi_probes.probe_kimi_read_guard(
                "kimi", doctor_runner=_DoctorFake())
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("ALLOWED", detail)

    def test_a_host_that_claims_no_read_confinement_is_unknown(self):
        state, by, _detail = kimi_probes.probe_kimi_read_guard("gemini")
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIsNone(by)


class TestKimiWriteGuardProbe(unittest.TestCase):
    def test_the_write_round_trip_is_proven(self):
        state, by, detail = kimi_probes.probe_kimi_write_guard("kimi")
        self.assertEqual(hosts.PROVEN, state)
        self.assertEqual(kimi_probes.KIMI_WRITE_GUARD, by)
        self.assertIn("round-trip", detail)

    def test_a_guard_failure_is_refuted_with_the_row_named(self):
        with mock.patch.object(kimi_probes, "_guard_round_trip",
                               return_value=(False, "the guard ALLOWED: Write outside the allowlist")):
            state, _by, detail = kimi_probes.probe_kimi_write_guard("kimi")
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("ALLOWED", detail)

    def test_a_host_that_claims_no_write_guard_is_unknown(self):
        state, by, _detail = kimi_probes.probe_kimi_write_guard("gemini")
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIsNone(by)


class TestKimiModelAliasProbe(unittest.TestCase):
    CONFIGURED = frozenset({"kimi-code/k3", "kimi-code/kimi-for-coding"})

    def test_every_role_binding_a_configured_alias_is_proven(self):
        state, by, detail = kimi_probes.probe_kimi_model_alias(
            "kimi", configured=self.CONFIGURED)
        self.assertEqual(hosts.PROVEN, state)
        self.assertEqual(kimi_probes.KIMI_MODEL_ALIAS, by)
        self.assertIn("kimi-code/k3", detail)

    def test_an_unresolvable_role_is_refuted_and_named(self):
        state, _by, detail = kimi_probes.probe_kimi_model_alias(
            "kimi", configured=frozenset({"kimi-code/k3"}))
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("scout", detail)

    def test_no_readable_model_table_is_refuted(self):
        state, _by, detail = kimi_probes.probe_kimi_model_alias("kimi", configured=frozenset())
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("no [models] table", detail)

    def test_a_host_that_claims_no_model_binding_is_unknown(self):
        state, by, _detail = kimi_probes.probe_kimi_model_alias("gemini")
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIsNone(by)


class TestKimiUsageWireProbe(unittest.TestCase):
    """I4: the ledger's channel is the PER-RUN home's wire files
    (`wire_path(self.kimi_home, session_id)`), not `~/.kimi-code/sessions`,
    which the runner's own KIMI_CODE_HOME override guarantees the children
    never write to. The probe proves the channel the runner reads."""

    def test_the_run_homes_wire_layout_resolves_and_parses(self):
        state, by, detail = kimi_probes.probe_kimi_usage_wire("kimi")
        self.assertEqual(hosts.PROVEN, state)
        self.assertEqual(kimi_probes.KIMI_USAGE_WIRE, by)
        self.assertIn("wire.jsonl", detail)

    def test_the_probe_takes_no_home_parameter_at_all(self):
        # N4: `run_probes`' `home=` means "a stand-in for ~" to the transcript
        # probe and meant "the per-run home to build the fixture in" here --
        # one parameter, two meanings, and #1618 renames the other consumer in
        # this exact neighbourhood. The kimi probe owns its own sandbox now, so
        # there is nothing to overload.
        import inspect
        self.assertEqual(["host"],
                         list(inspect.signature(kimi_probes.probe_kimi_usage_wire).parameters))

    def test_the_fixture_session_never_lands_outside_the_probes_sandbox(self):
        # N4: the probe used to take `run_probes`' `home=` -- a parameter that
        # means "a stand-in for ~" to the OTHER consumer -- and wrote its
        # fixture session there, cleaning only its own sandbox. It now has no
        # such parameter: every path it writes is inside the tempdir it owns.
        before = set(os.listdir(tempfile.gettempdir()))
        _state, _by, detail = kimi_probes.probe_kimi_usage_wire("kimi")
        after = set(os.listdir(tempfile.gettempdir()))
        self.assertEqual(set(), after - before)
        home = detail.split("run home ", 1)[1].split(" ", 1)[0]
        self.assertFalse(os.path.exists(home))     # the sandbox is gone with it

    def test_a_layout_wire_path_cannot_resolve_is_refuted(self):
        import scripts.runners.kimi as kimi_runner
        with mock.patch.object(kimi_runner, "wire_path", return_value=None):
            state, _by, detail = kimi_probes.probe_kimi_usage_wire("kimi")
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("wire.jsonl", detail)

    def test_a_parser_that_returns_the_wrong_figures_is_refuted(self):
        import scripts.runners.kimi as kimi_runner
        with mock.patch.object(kimi_runner, "parse_wire", return_value=({}, None)):
            state, _by, detail = kimi_probes.probe_kimi_usage_wire("kimi")
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("expected", detail)

    def test_a_host_that_claims_no_usage_ledger_is_unknown(self):
        state, by, _detail = kimi_probes.probe_kimi_usage_wire("gemini")
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIsNone(by)


class TestKimiLaunchGuard(unittest.TestCase):
    """I3: the suite must never launch the real `kimi` binary, and that must be
    STRUCTURAL rather than a property of today's call sites.

    Every kimi spawn resolves its runner from a module attribute
    (one `DEFAULT_RUNNER` per seam module, N1), which
    tests/conftest.py's autouse `_no_live_host_launches` swaps for a refusal.
    The probes must let that refusal PROPAGATE: mapping it to UNKNOWN would
    turn "the suite tried to launch kimi" into a quiet probe state.
    """

    def test_run_probes_refuses_to_launch_the_real_binary(self):
        import scripts.runners.base as runners_base
        with tempfile.TemporaryDirectory() as d:
            home = os.path.join(d, "fixture-home")
            os.makedirs(home)
            with open(os.path.join(home, "config.toml"), "w", encoding="utf-8") as fh:
                fh.write('default_model = "kimi-code/k3"\n')
            registration = os.path.join(d, "agents")
            _kimi_fully_registered(registration)
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": home}), \
                 self.assertRaises(runners_base.LaunchRefused) as caught:
                host_probes.run_probes("kimi", d, session_root=d,
                                       registration_dir=registration)
        self.assertIn("kimi", str(caught.exception))

    def test_every_kimi_spawn_seam_carries_one_module_level_DEFAULT_RUNNER(self):
        # N1: #1619's launch guard FINDS seams by AST walk and then asserts
        # `hasattr(module, "DEFAULT_RUNNER")` on each -- one attribute per
        # MODULE, not one per family. A module-scoped name is what survives
        # the rebase; `KIMI_DEFAULT_RUNNER` would fail that test twice. #1627
        # moved the probe seam from `host_probes` to `probes/kimi.py`, the one
        # probe module that starts a host CLI, so that is the module the
        # attribute has to be on now.
        import scripts.runners.base as runners_base
        import scripts.runners.kimi as kimi_runner
        for module in (kimi_probes, kimi_runner):
            self.assertTrue(hasattr(module, "DEFAULT_RUNNER"),
                            "%s has no module-level DEFAULT_RUNNER" % module.__name__)
            with self.assertRaises(runners_base.LaunchRefused):
                module.DEFAULT_RUNNER(["kimi", "--version"])

    def test_the_runner_resolves_its_launcher_from_the_module_attribute(self):
        import scripts.runners.base as runners_base
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
                with self.assertRaises(runners_base.LaunchRefused):
                    runner.run_entry({"id": "e1", "model": "secondary",
                                      "prompt": "x"}, {})


def _kimi_armed_config_without(mode):
    """A `build_merged_config` that arms every hook EXCEPT `mode`'s -- the
    mutation the guardrails demand of a probe whose id says "armed".

    The mode is read out of the command's ARGV, not out of its text: since
    #1633 the command is shell-quoted, so `" read "` (quote, mode, quote) --
    which relied on the old `"%s" read "%s"` spelling -- matched nothing, and
    this mutation silently dropped no hook at all."""
    import scripts.runners.kimi as kimi_runner
    real = kimi_runner.build_merged_config

    def mutated(source, scope_path, allowlist_path, *args, **kwargs):
        merged = real(source, scope_path, allowlist_path, *args, **kwargs)
        merged["hooks"] = [h for h in merged["hooks"]
                           if mode not in shlex.split(h.get("command") or "")]
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
            read = kimi_probes.probe_kimi_read_guard("kimi", doctor_runner=_DoctorFake())
            write = kimi_probes.probe_kimi_write_guard("kimi")
        for state, by, detail in (read, write):
            self.assertEqual(hosts.REFUTED, state, detail)
            self.assertIn("PreToolUse", detail)

    def test_dropping_the_read_hook_refutes_the_read_probe(self):
        import scripts.runners.kimi as kimi_runner
        with mock.patch.object(kimi_runner, "build_merged_config",
                               side_effect=_kimi_armed_config_without("read")):
            state, _by, detail = kimi_probes.probe_kimi_read_guard(
                "kimi", doctor_runner=_DoctorFake())
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("Read", detail)

    def test_dropping_the_write_hook_refutes_the_write_probe(self):
        import scripts.runners.kimi as kimi_runner
        with mock.patch.object(kimi_runner, "build_merged_config",
                               side_effect=_kimi_armed_config_without("write")):
            state, _by, detail = kimi_probes.probe_kimi_write_guard("kimi")
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("Write", detail)

    def test_dropping_the_read_hook_does_not_refute_the_write_guard(self):
        # N7: over-refutation never blesses anything, but a reader scanning
        # STATES would believe artifact_write_guard was broken when only read
        # confinement is. Each probe owns its own matcher and merely notes the
        # other's.
        import scripts.runners.kimi as kimi_runner
        with mock.patch.object(kimi_runner, "build_merged_config",
                               side_effect=_kimi_armed_config_without("read")):
            state, _by, detail = kimi_probes.probe_kimi_write_guard("kimi")
        self.assertEqual(hosts.PROVEN, state)
        self.assertIn("Read", detail)                 # the miss is still disclosed
        self.assertIn("read guard probe", detail)

    def test_dropping_the_write_hook_does_not_refute_read_confinement(self):
        import scripts.runners.kimi as kimi_runner
        with mock.patch.object(kimi_runner, "build_merged_config",
                               side_effect=_kimi_armed_config_without("write")):
            state, _by, detail = kimi_probes.probe_kimi_read_guard(
                "kimi", doctor_runner=_DoctorFake())
        self.assertEqual(hosts.PROVEN, state)
        self.assertIn("Write", detail)
        self.assertIn("write guard probe", detail)

    def test_a_hook_pointing_at_a_nonexistent_script_is_refuted(self):
        import scripts.runners.kimi as kimi_runner
        with mock.patch.object(kimi_runner, "_GUARD", "/nonexistent/kimi_guard_hook.py"):
            state, _by, detail = kimi_probes.probe_kimi_write_guard("kimi")
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("guard script", detail)

    def test_a_config_the_writer_corrupts_is_refuted(self):
        import scripts.kimi_toml as kimi_toml
        with mock.patch.object(kimi_toml, "dump_toml",
                               side_effect=lambda config: "[[mcp]]\nname = \n"):
            state, _by, detail = kimi_probes.probe_kimi_write_guard("kimi")
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
            state, _by, detail = kimi_probes.probe_kimi_write_guard("kimi")
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("tools.disabled", detail)

    def test_the_armed_detail_names_the_config_it_parsed(self):
        state, _by, detail = kimi_probes.probe_kimi_write_guard("kimi")
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
            state, _by, detail = kimi_probes.probe_kimi_shell_surface(
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
                state, _by, detail = kimi_probes.probe_kimi_shell_surface(
                    "kimi", registration_dir=d, version="0.42")
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("FetchURL", detail)

    def test_a_config_the_probe_cannot_generate_is_refuted_not_proven(self):
        # R2-4: this is OUR writer failing, not third-party data the probe
        # cannot read (I5's tolerated fallback). A probe that could not build
        # the artifact it measures may not report `proven` with the reason
        # tucked into its detail.
        with tempfile.TemporaryDirectory() as d:
            _kimi_fully_registered(d)
            with mock.patch.object(kimi_probes, "_kimi_armed_home",
                                   side_effect=OSError("no space left on device")):
                state, _by, detail = kimi_probes.probe_kimi_shell_surface(
                    "kimi", registration_dir=d, version="0.42")
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("no space left on device", detail)

    def test_every_exception_the_writer_raises_is_reported_not_raised(self):
        # `build_merged_config` raises ValueError (M3/N5) and `dump_toml`
        # raises TypeError (C2); neither was caught, and `run_probes` wraps no
        # probe, so posture establishment would have died on a traceback.
        import scripts.kimi_toml as kimi_toml
        import scripts.runners.kimi as kimi_runner
        for target, boom in ((kimi_toml, TypeError("cannot emit TOML")),
                             (kimi_runner, ValueError("expected a table at `tools`"))):
            name = "dump_toml" if target is kimi_toml else "build_merged_config"
            with self.subTest(raises=type(boom).__name__):
                with tempfile.TemporaryDirectory() as d:
                    _kimi_fully_registered(d)
                    with mock.patch.object(target, name, side_effect=boom):
                        state, _by, detail = kimi_probes.probe_kimi_shell_surface(
                            "kimi", registration_dir=d, version="0.42")
                self.assertEqual(hosts.REFUTED, state)
                self.assertIn(str(boom), detail)

    def test_a_tool_that_is_neither_granted_nor_disabled_is_refuted(self):
        import scripts.runners.kimi as kimi_runner
        with tempfile.TemporaryDirectory() as d:
            _kimi_fully_registered(d)
            with mock.patch.object(kimi_runner, "disabled_tools",
                                   side_effect=lambda vocabulary=None: ["Bash"]):
                state, _by, detail = kimi_probes.probe_kimi_shell_surface(
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
            state, _by, detail = kimi_probes.probe_kimi_shell_surface(
                "kimi", registration_dir=d, version="0.42",
                run_home=self._home(snapshot=["Read", "Grep", "Glob", "Write"]))
        self.assertEqual(hosts.PROVEN, state)
        self.assertIn("tools_snapshot", detail)
        self.assertIn("panopticon-domain-panel", detail)

    def test_a_snapshot_wider_than_the_grant_is_refuted_naming_both_sets(self):
        with tempfile.TemporaryDirectory() as d:
            _kimi_fully_registered(d)
            state, _by, detail = kimi_probes.probe_kimi_shell_surface(
                "kimi", registration_dir=d, version="0.42",
                run_home=self._home(snapshot=["Read", "Grep", "Glob", "Write", "Bash"]))
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("Bash", detail)
        self.assertIn("panopticon-domain-panel", detail)

    def test_no_wire_file_yet_falls_back_to_the_table_and_says_so(self):
        with tempfile.TemporaryDirectory() as d:
            _kimi_fully_registered(d)
            state, _by, detail = kimi_probes.probe_kimi_shell_surface(
                "kimi", registration_dir=d, version="0.42", run_home=self._home())
        self.assertEqual(hosts.PROVEN, state)
        self.assertIn("no child wire file", detail)
        self.assertIn("rests on the version table", detail)

    def test_no_run_home_at_all_falls_back_rather_than_looking_for_one(self):
        with tempfile.TemporaryDirectory() as d:
            _kimi_fully_registered(d)
            state, _by, detail = kimi_probes.probe_kimi_shell_surface(
                "kimi", registration_dir=d, version="0.42")
        self.assertEqual(hosts.PROVEN, state)
        self.assertIn("no per-run kimi home yet", detail)

    def test_a_planted_pointer_and_wire_file_in_the_tree_are_never_read(self):
        # N2, the forged-evidence half. A target that plants both a pointer
        # file in the run folder and the directory it names cannot make this
        # probe report an effective surface.
        #
        # R2-1: the round-2 version of this test omitted `run_dir=` -- the
        # argument the attack needed and the one `run_probes` passed in
        # production -- so it passed on the vulnerable tree, which is the one
        # thing a test named for this must not do. The invariant is that the
        # channel does not EXIST, so that is what is asserted: the keyword is
        # refused outright, and the call production makes reports nothing the
        # planted directory contains.
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
            with self.assertRaises(TypeError):        # no tree-reading channel
                kimi_probes.probe_kimi_shell_surface(
                    "kimi", registration_dir=registration, version="0.42",
                    run_dir=run_dir)
            state, _by, detail = kimi_probes.probe_kimi_shell_surface(
                "kimi", registration_dir=registration, version="0.42")
        self.assertEqual(hosts.PROVEN, state)
        self.assertNotIn("Bash", detail)
        self.assertNotIn("tools_snapshot for", detail)
        self.assertNotIn("run_dir",
                         inspect.signature(kimi_probes.probe_kimi_shell_surface).parameters)
