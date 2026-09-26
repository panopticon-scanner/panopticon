"""The kimi family's probes: `scripts.probes.kimi` (#1627 split these out of
tests/test_host_probes.py; the tests themselves are unchanged)."""
import inspect
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import dispatch, host_probes, hosts
import scripts.probes.common as probes_common
import scripts.probes.kimi as kimi_probes
import scripts.probes.kimi_snapshot as kimi_snapshot
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
            import scripts.runners.kimi_home as kimi_home
            narrow = {"0.42": kimi_home.TOOL_VOCABULARY["0.42"] - {"Read", "Bash"}}
            with mock.patch.dict(kimi_home.TOOL_VOCABULARY, narrow):
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

    def test_version_runner_failures_leave_the_tool_vocabulary_unknown(self):
        failures = (FileNotFoundError("synthetic missing kimi"),
                    subprocess.TimeoutExpired(["kimi", "--version"], 15))
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                with tempfile.TemporaryDirectory() as d:
                    _kimi_fully_registered(d)
                    runner = mock.Mock(side_effect=failure)
                    state, by, detail = kimi_probes.probe_kimi_shell_surface(
                        "kimi", registration_dir=d, runner=runner)
                runner.assert_called_once_with(
                    ["kimi", "--version"], capture_output=True, text=True, timeout=15)
                self.assertEqual(hosts.UNKNOWN, state)
                self.assertEqual(kimi_probes.KIMI_SHELL_SURFACE, by)
                self.assertIn("version could not be determined", detail)

    def test_version_launch_refusal_propagates(self):
        import scripts.runners.base as runners_base
        with tempfile.TemporaryDirectory() as d:
            _kimi_fully_registered(d)
            runner = mock.Mock(side_effect=runners_base.LaunchRefused("synthetic kimi launch"))
            with self.assertRaisesRegex(runners_base.LaunchRefused, "synthetic kimi launch"):
                kimi_probes.probe_kimi_shell_surface(
                    "kimi", registration_dir=d, runner=runner)
        runner.assert_called_once_with(
            ["kimi", "--version"], capture_output=True, text=True, timeout=15)

    def test_a_host_that_registers_no_shells_is_unknown(self):
        state, by, _detail = kimi_probes.probe_kimi_shell_surface("gemini", version="0.42")
        self.assertEqual(hosts.UNKNOWN, state)
        self.assertIsNone(by)


class TestKimiGuardRoundTrip(unittest.TestCase):
    """Drive the real round-trip function through an injected subprocess seam."""

    def test_multirow_round_trip_binds_json_mode_path_and_entry(self):
        import scripts.kimi_guard_hook as kimi_guard_hook

        with tempfile.TemporaryDirectory() as d:
            data_path = os.path.join(d, "scope.json")
            guard_path = os.path.join(d, "fixture-guard.py")
            rows = [("allowed first", {"tool_name": "Read", "path": "inside"},
                     "entry-1", True),
                    ("denied second", {"tool_name": "Read", "path": "outside"},
                     "entry-2", False),
                    ("allowed unbound", {"tool_name": "Read", "path": "public"},
                     None, True)]
            outputs = iter(("{}", json.dumps({"hookSpecificOutput": {
                "permissionDecision": "deny"}}), "{}"))
            calls = []

            def runner(command, **kwargs):
                calls.append((command, kwargs))
                return subprocess.CompletedProcess(command, 0, stdout=next(outputs), stderr="")

            ok, detail = kimi_probes._guard_round_trip(
                "read", data_path, rows, guard_path=guard_path, runner=runner)

        self.assertTrue(ok, detail)
        self.assertIn("read round-trip: 3/3 payloads", detail)
        self.assertIn("fixture-guard.py", detail)
        self.assertEqual(3, len(calls))
        for (command, kwargs), (_name, payload, entry_id, _allowed) in zip(calls, rows):
            self.assertEqual([sys.executable, guard_path, "read", data_path], command)
            self.assertEqual(payload, json.loads(kwargs["input"]))
            self.assertEqual({"capture_output": True, "text": True, "timeout": 30},
                             {key: kwargs[key] for key in ("capture_output", "text", "timeout")})
            self.assertEqual(os.environ.get("PATH", ""), kwargs["env"]["PATH"])
            if entry_id is None:
                self.assertNotIn(kimi_guard_hook.ENV_ENTRY_ID, kwargs["env"])
            else:
                self.assertEqual(entry_id, kwargs["env"][kimi_guard_hook.ENV_ENTRY_ID])

    def test_guard_launcher_failure_reports_the_exception(self):
        for failure in (FileNotFoundError("synthetic missing guard"),
                        subprocess.TimeoutExpired([sys.executable, "guard.py"], 30)):
            with self.subTest(failure=type(failure).__name__):
                with tempfile.TemporaryDirectory() as d:
                    runner = mock.Mock(side_effect=failure)
                    ok, detail = kimi_probes._guard_round_trip(
                        "read", os.path.join(d, "scope.json"),
                        [("allowed fixture", {}, "entry-1", True)], runner=runner)
                self.assertFalse(ok)
                self.assertIn("the guard-hook subprocess could not run", detail)
                self.assertIn(type(failure).__name__, detail)
                runner.assert_called_once()

    def test_unexpected_allow_names_first_failing_row_and_bounds_stdout(self):
        marker = "TAIL-MARKER"
        stdout = "allowed " + "x" * 180 + marker
        runner = mock.Mock(return_value=mock.Mock(stdout=stdout))
        rows = [("outside read must be denied", {"path": "outside"}, "entry-1", False),
                ("later row must not run", {"path": "inside"}, "entry-2", True)]
        ok, detail = kimi_probes._guard_round_trip("read", "scope.json", rows, runner=runner)
        self.assertFalse(ok)
        self.assertIn("the guard ALLOWED: outside read must be denied", detail)
        self.assertIn("(stdout: " + stdout[:160] + ")", detail)
        self.assertNotIn(marker, detail)
        runner.assert_called_once()

    def test_unexpected_deny_names_first_failing_row_and_stops(self):
        stdout = json.dumps({"hookSpecificOutput": {"permissionDecision": "deny"}})
        runner = mock.Mock(return_value=mock.Mock(stdout=stdout))
        rows = [("inside read must be allowed", {"path": "inside"}, "entry-1", True),
                ("later row must not run", {"path": "outside"}, "entry-2", False)]
        ok, detail = kimi_probes._guard_round_trip("read", "scope.json", rows, runner=runner)
        self.assertFalse(ok)
        self.assertIn("the guard DENIED: inside read must be allowed", detail)
        self.assertNotIn("later row must not run", detail)
        runner.assert_called_once()


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
        # F4: the data-file refutations are a stated requirement of this probe
        # (#1571) and nothing asserted they ran -- deleting the whole `corrupt`
        # loop left every test green. The detail is composed from what each
        # leg reported, so naming the legs here is what makes their absence a
        # failure rather than a shorter string nobody reads.
        for leg in ("malformed allowlist", "version-1 flat list",
                    "v2 document with no entries"):
            with self.subTest(leg=leg):
                self.assertIn(leg, detail)

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

    def _profile_model(self, role):
        """The FILE's own value for this role -- the declaration that licenses
        an unbound role, read directly rather than through resolve_model."""
        profiles = kimi_probes.model_resolver._profiles()
        return (((profiles.get("hosts") or {}).get("kimi") or {}).get(role) or {}).get("model")

    def test_only_a_profile_declared_null_role_may_be_unbound(self):
        # #1737 fix round 1, nit (c). The unbound allowance must be spendable
        # only by a role the profile DECLARES null. A role that merely lost its
        # tier would otherwise be skipped as "deliberately unbound" and launch
        # on the session's model with nothing saying so.
        declared = {role for role in probes_common.DRIVER_ROLES
                    if self._profile_model(role) is None}
        self.assertEqual({"setup_scan"}, declared)       # the canary
        resolved_null = {role for role in probes_common.DRIVER_ROLES
                         if kimi_probes.model_resolver.resolve_model("kimi", role)
                         .get("model") is None}
        self.assertEqual(declared, resolved_null)
        # ...and with the profile file unreadable, the hardcoded fallback --
        # the table `_normalize_kimi_model` would otherwise coerce -- agrees.
        with mock.patch.object(kimi_probes.model_resolver, "_profiles", return_value={}):
            fallback_null = {role for role in probes_common.DRIVER_ROLES
                             if kimi_probes.model_resolver.resolve_model("kimi", role)
                             .get("model") is None}
        self.assertEqual(declared, fallback_null)

    def test_the_probe_names_exactly_the_declared_role_as_unbound(self):
        state, _by, detail = kimi_probes.probe_kimi_model_alias(
            "kimi", configured=self.CONFIGURED)
        self.assertEqual(hosts.PROVEN, state)
        bound, _, unbound = detail.partition(
            "; deliberately unbound, the session's model runs: ")
        self.assertEqual({"setup_scan"}, set(unbound.split(", ")))
        for role in probes_common.DRIVER_ROLES:
            self.assertEqual(role != "setup_scan", ("%s->" % role) in bound, role)

    def test_a_deliberately_unbound_role_is_named_not_refuted(self):
        # #1737 R-F4-2: `setup_scan`'s profile resolves to None -- inherit the
        # session's model -- and `runners/kimi.py` binds `-m` only for an entry
        # that carries one, so there is no alias for it to fail to resolve.
        state, _by, detail = kimi_probes.probe_kimi_model_alias(
            "kimi", configured=self.CONFIGURED)
        self.assertEqual(hosts.PROVEN, state)
        self.assertIn("deliberately unbound", detail)
        self.assertIn("setup_scan", detail)

    def test_every_role_inheriting_measures_nothing_and_says_so(self):
        with mock.patch.object(kimi_probes.model_resolver, "resolve_model",
                               return_value={"model": None}):
            state, _by, detail = kimi_probes.probe_kimi_model_alias(
                "kimi", configured=self.CONFIGURED)
        self.assertEqual(hosts.UNKNOWN, state)     # never a vacuous PROVEN
        self.assertIn("no role carries an entry model", detail)

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
        import scripts.runners.kimi as kimi_runner

        real_tempdir = tempfile.TemporaryDirectory
        real_wire_path = kimi_runner.wire_path
        sandboxes = []
        wire_paths = []

        with real_tempdir(prefix="kimi test parent ") as parent:
            parent = Path(parent)
            sibling = parent / "unrelated sibling.txt"
            sibling.write_text("unrelated work", encoding="utf-8")

            def sandbox_tempdir(*args, **kwargs):
                self.assertNotIn("dir", kwargs)
                temporary = real_tempdir(*args, dir=parent, **kwargs)
                sandboxes.append(Path(temporary.name))
                return temporary

            def observed_wire_path(run_home, session_id):
                self.assertEqual(1, len(sandboxes))
                sandbox = sandboxes[0].resolve(strict=True)
                home = Path(run_home).resolve(strict=True)
                resolved = real_wire_path(run_home, session_id)
                self.assertIsNotNone(resolved)
                wire = Path(resolved).resolve(strict=True)
                self.assertTrue(home.is_relative_to(sandbox))
                self.assertTrue(wire.is_relative_to(sandbox))
                self.assertTrue(wire.is_file())
                wire_paths.append((home, wire))
                return resolved

            with mock.patch.object(tempfile, "TemporaryDirectory",
                                   side_effect=sandbox_tempdir), \
                 mock.patch.object(kimi_runner, "wire_path",
                                   side_effect=observed_wire_path):
                state, by, _detail = kimi_probes.probe_kimi_usage_wire("kimi")

            self.assertEqual(hosts.PROVEN, state)
            self.assertEqual(kimi_probes.KIMI_USAGE_WIRE, by)
            self.assertEqual(1, len(sandboxes))
            self.assertEqual(1, len(wire_paths))
            sandbox = sandboxes[0]
            home, wire = wire_paths[0]
            self.assertFalse(sandbox.exists())
            self.assertFalse(home.exists())
            self.assertFalse(wire.exists())
            self.assertTrue(sibling.is_file())

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
    import scripts.runners.kimi_home as kimi_home
    real = kimi_home.build_merged_config

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
        import scripts.runners.kimi_home as kimi_home
        with mock.patch.object(kimi_home, "build_merged_config",
                               side_effect=lambda source, s, a, *x, **k: {"tools": {"disabled": []}}):
            read = kimi_probes.probe_kimi_read_guard("kimi", doctor_runner=_DoctorFake())
            write = kimi_probes.probe_kimi_write_guard("kimi")
        for state, by, detail in (read, write):
            self.assertEqual(hosts.REFUTED, state, detail)
            self.assertIn("PreToolUse", detail)

    def test_dropping_the_read_hook_refutes_the_read_probe(self):
        import scripts.runners.kimi_home as kimi_home
        with mock.patch.object(kimi_home, "build_merged_config",
                               side_effect=_kimi_armed_config_without("read")):
            state, _by, detail = kimi_probes.probe_kimi_read_guard(
                "kimi", doctor_runner=_DoctorFake())
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("Read", detail)

    def test_dropping_the_write_hook_refutes_the_write_probe(self):
        import scripts.runners.kimi_home as kimi_home
        with mock.patch.object(kimi_home, "build_merged_config",
                               side_effect=_kimi_armed_config_without("write")):
            state, _by, detail = kimi_probes.probe_kimi_write_guard("kimi")
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("Write", detail)

    def test_dropping_the_read_hook_does_not_refute_the_write_guard(self):
        # N7: over-refutation never blesses anything, but a reader scanning
        # STATES would believe artifact_write_guard was broken when only read
        # confinement is. Each probe owns its own matcher and merely notes the
        # other's.
        import scripts.runners.kimi_home as kimi_home
        with mock.patch.object(kimi_home, "build_merged_config",
                               side_effect=_kimi_armed_config_without("read")):
            state, _by, detail = kimi_probes.probe_kimi_write_guard("kimi")
        self.assertEqual(hosts.PROVEN, state)
        self.assertIn("Read", detail)                 # the miss is still disclosed
        self.assertIn("read guard probe", detail)

    def test_dropping_the_write_hook_does_not_refute_read_confinement(self):
        import scripts.runners.kimi_home as kimi_home
        with mock.patch.object(kimi_home, "build_merged_config",
                               side_effect=_kimi_armed_config_without("write")):
            state, _by, detail = kimi_probes.probe_kimi_read_guard(
                "kimi", doctor_runner=_DoctorFake())
        self.assertEqual(hosts.PROVEN, state)
        self.assertIn("Write", detail)
        self.assertIn("write guard probe", detail)

    def test_a_hook_pointing_at_a_nonexistent_script_is_refuted(self):
        import scripts.runners.kimi_home as kimi_home
        with mock.patch.object(kimi_home, "_GUARD", "/nonexistent/kimi_guard_hook.py"):
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
        import scripts.runners.kimi_home as kimi_home
        real = kimi_home.build_merged_config

        def without_disabled(source, scope_path, allowlist_path, *args, **kwargs):
            merged = real(source, scope_path, allowlist_path, *args, **kwargs)
            merged["tools"] = {"disabled": []}
            return merged
        with mock.patch.object(kimi_home, "build_merged_config",
                               side_effect=without_disabled):
            state, _by, detail = kimi_probes.probe_kimi_write_guard("kimi")
        self.assertEqual(hosts.REFUTED, state)
        self.assertIn("tools.disabled", detail)

    def test_an_armed_config_with_live_mcp_refutes_both_probes(self):
        # #1640: the per-run home mediates what it can guard, and MCP tools
        # are outside both hooks -- so an armed config whose `[mcp]` block is
        # live is a refutation of the arming, exactly as a missing hook or a
        # gutted `tools.disabled` is. Shared between the two probes for the
        # same reason `tools.disabled` is: neither guard covers those tools.
        import scripts.runners.kimi_home as kimi_home
        real = kimi_home.build_merged_config

        for name, block in (("enabled", {"enabled": True, "servers": []}),
                            ("servers", {"enabled": False,
                                         "servers": [{"name": "s1", "command": "x"}]})):
            def with_mcp(source, scope_path, allowlist_path, *args, **kwargs):
                merged = real(source, scope_path, allowlist_path, *args, **kwargs)
                merged["mcp"] = block
                return merged
            with self.subTest(live=name):
                with mock.patch.object(kimi_home, "build_merged_config",
                                       side_effect=with_mcp):
                    read = kimi_probes.probe_kimi_read_guard(
                        "kimi", doctor_runner=_DoctorFake())
                    write = kimi_probes.probe_kimi_write_guard("kimi")
                for state, _by, detail in (read, write):
                    self.assertEqual(hosts.REFUTED, state, detail)
                    self.assertIn("mcp", detail)

    def test_an_armed_config_whose_mcp_block_is_not_the_inert_one_refutes(self):
        # Fix round 1, F2: the coercions this used to make -- `mcp` to `{}` and
        # `servers` to `[]` when either was not the expected type -- both fail
        # OPEN. An ABSENT block, a scalar `mcp`, or a `servers` this cannot
        # read are not evidence that MCP is off; they are the absence of
        # evidence, and a probe named "...-armed" may not bless them. Measured
        # on the base: all three reported `proven` on BOTH guard probes, so a
        # refactor that dropped the `merged["mcp"]` assignment would have
        # shipped a per-run home carrying the operator's MCP defaults.
        import scripts.runners.kimi_home as kimi_home
        real = kimi_home.build_merged_config

        shapes = (("absent", None),
                  ("scalar", "live-and-dangerous"),
                  ("servers not an array", {"enabled": False, "servers": "hostile"}))
        for name, block in shapes:
            # Fix round 2 (N2): KEYWORD-ONLY. `_block` sat in the fourth
            # POSITIONAL slot, which is `build_merged_config`'s `source_path`.
            # The real call site passes that by keyword so this was correct,
            # but a call site that ever passed it positionally would bind a
            # path string into `_block`, every subTest would patch
            # `merged["mcp"] = "<some path>"`, and the test would still pass
            # (a path is also != the inert block) while testing none of the
            # three shapes it names.
            def armed(source, scope_path, allowlist_path, *args, _block=block, **kwargs):
                merged = real(source, scope_path, allowlist_path, *args, **kwargs)
                if _block is None:
                    merged.pop("mcp", None)
                else:
                    merged["mcp"] = _block
                return merged
            with self.subTest(shape=name):
                with mock.patch.object(kimi_home, "build_merged_config",
                                       side_effect=armed):
                    read = kimi_probes.probe_kimi_read_guard(
                        "kimi", doctor_runner=_DoctorFake())
                    write = kimi_probes.probe_kimi_write_guard("kimi")
                for state, _by, detail in (read, write):
                    self.assertEqual(hosts.REFUTED, state, detail)
                    self.assertIn("mcp", detail)

    def test_the_probes_bar_is_re_derived_and_cannot_be_moved(self):
        # Fix round 2 (N3), from the probe's side: the equality bar is a fresh
        # value per call, so mutating what a previous call handed out moves
        # nothing. Both halves are asserted -- the PROVEN path still proves,
        # and a live block still refutes -- because a bar that had been moved
        # would break exactly one of them.
        import scripts.kimi_toml as kimi_toml
        import scripts.runners.kimi_home as kimi_home
        stolen = kimi_toml.inert_mcp()
        stolen["enabled"] = True
        stolen["servers"].append({"name": "planted"})
        state, _by, detail = kimi_probes.probe_kimi_write_guard("kimi")
        self.assertEqual(hosts.PROVEN, state, detail)
        real = kimi_home.build_merged_config

        def live(source, scope_path, allowlist_path, *args, **kwargs):
            merged = real(source, scope_path, allowlist_path, *args, **kwargs)
            merged["mcp"] = {"enabled": True, "servers": [{"name": "planted"}]}
            return merged
        with mock.patch.object(kimi_home, "build_merged_config", side_effect=live):
            state, _by, detail = kimi_probes.probe_kimi_write_guard("kimi")
        self.assertEqual(hosts.REFUTED, state, detail)

    def test_the_armed_detail_names_the_config_it_parsed(self):
        state, _by, detail = kimi_probes.probe_kimi_write_guard("kimi")
        self.assertEqual(hosts.PROVEN, state)
        self.assertIn("config.toml", detail)

    def test_prepare_refuses_to_run_without_the_guard_script(self):
        import scripts.runners.kimi as kimi_runner
        import scripts.runners.kimi_home as kimi_home
        with tempfile.TemporaryDirectory() as d:
            home = os.path.join(d, "fixture-home")
            os.makedirs(home)
            with open(os.path.join(home, "config.toml"), "w", encoding="utf-8") as fh:
                fh.write('default_model = "kimi-code/k3"\n')
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": home}), \
                 mock.patch.object(kimi_home, "_GUARD", os.path.join(d, "gone.py")):
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
        import scripts.runners.kimi_home as kimi_home
        real = kimi_home.build_merged_config

        def disables_nothing(source, scope_path, allowlist_path, *args, **kwargs):
            merged = real(source, scope_path, allowlist_path, *args, **kwargs)
            merged["tools"] = {"disabled": []}
            return merged
        with tempfile.TemporaryDirectory() as d:
            _kimi_fully_registered(d)
            with mock.patch.object(kimi_home, "build_merged_config",
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
            with mock.patch.object(kimi_snapshot, "_kimi_armed_home",
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
        import scripts.runners.kimi_home as kimi_home
        for target, boom in ((kimi_toml, TypeError("cannot emit TOML")),
                             (kimi_home, ValueError("expected a table at `tools`"))):
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
        import scripts.runners.kimi_home as kimi_home
        with tempfile.TemporaryDirectory() as d:
            _kimi_fully_registered(d)
            with mock.patch.object(kimi_home, "disabled_tools",
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
        import scripts.runners.kimi_home as kimi_home
        home = tempfile.mkdtemp(prefix=kimi_home.HOME_PREFIX)
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

    def _wire(self, home, session, lines, mtime):
        wire = os.path.join(home, "sessions", "wd_1", session,
                            "agents", "main", "wire.jsonl")
        os.makedirs(os.path.dirname(wire))
        with open(wire, "w", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")
        os.utime(wire, (mtime, mtime))
        return wire

    def test_snapshot_accepts_each_agent_key_and_object_named_tools(self):
        for agent_key in ("agent", "agentName", "agent_file", "agentFile"):
            with self.subTest(agent_key=agent_key):
                home = self._home()
                wire = self._wire(home, "session_x", [
                    "{corrupt json",
                    json.dumps(["not an object"]),
                    json.dumps({"type": "llm.request", "tools": ["ignored"]}),
                    json.dumps({"type": "llm.tools_snapshot", "tools": "not a list",
                                agent_key: "ignored.md"}),
                    json.dumps({"type": "llm.tools_snapshot", "tools": [
                        {"name": "Read"}, "Grep", {"other": "ignored"}],
                        agent_key: "/registered/agents/scout.md"})], mtime=100)
                tools, agent, source = kimi_snapshot._kimi_wire_snapshot(home)
                self.assertEqual({"Read", "Grep"}, tools)
                self.assertEqual("scout", agent)
                self.assertEqual(wire, source)

    def test_snapshot_selects_newest_valid_wire_across_mtimes(self):
        home = self._home()
        self._wire(home, "old_valid", [json.dumps({
            "type": "llm.tools_snapshot", "agent": "old.md", "tools": ["Read"]})],
            mtime=100)
        newest_valid = self._wire(home, "new_valid", [json.dumps({
            "type": "llm.tools_snapshot", "agentName": "new.md",
            "tools": [{"name": "Write"}]})], mtime=200)
        self._wire(home, "newest_invalid", [
            "{corrupt json", json.dumps({"type": "llm.tools_snapshot",
                                         "agent": "invalid.md", "tools": {"name": "Bash"}})],
            mtime=300)
        tools, agent, source = kimi_snapshot._kimi_wire_snapshot(home)
        self.assertEqual({"Write"}, tools)
        self.assertEqual("new", agent)
        self.assertEqual(newest_valid, source)

    def test_invalid_wires_have_no_snapshot_and_probe_falls_back_to_table(self):
        home = self._home()
        self._wire(home, "invalid", [
            "{corrupt json", json.dumps(["not an object"]),
            json.dumps({"type": "llm.tools_snapshot", "agent": "scout.md",
                        "tools": {"name": "Bash"}})], mtime=100)
        tools, agent, reason = kimi_snapshot._kimi_wire_snapshot(home)
        self.assertIsNone(tools)
        self.assertIsNone(agent)
        self.assertIn("no child wire file", reason)
        with tempfile.TemporaryDirectory() as registration:
            _kimi_fully_registered(registration)
            state, by, detail = kimi_probes.probe_kimi_shell_surface(
                "kimi", registration_dir=registration, version="0.42", run_home=home)
        self.assertEqual(hosts.PROVEN, state)
        self.assertEqual(kimi_probes.KIMI_SHELL_SURFACE, by)
        self.assertIn("no child wire file", detail)
        self.assertIn("rests on the version table", detail)

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
        import scripts.runners.kimi_home as kimi_home
        planted = self._home(snapshot=["Bash", "FetchURL"])
        with tempfile.TemporaryDirectory() as d:
            registration = os.path.join(d, "agents")
            _kimi_fully_registered(registration)
            run_dir = os.path.join(d, "run")
            os.makedirs(run_dir)
            with open(os.path.join(run_dir, kimi_home.POINTER_FILE), "w",
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
