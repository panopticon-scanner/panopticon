"""Setup readiness and host posture behavior."""

import dataclasses
import os
import unittest
from unittest import mock


import scripts.host_disclosure as host_disclosure
import scripts.host_probes as host_probes
import scripts.hosts as hosts
import scripts.probes.common as probes_common
import scripts.setup_flow as setup_flow


from tests.setup_helpers import (
    _isolate_codex_probes,
    _repo,
    _mixed_artifact,
    _all_proven_artifact,
    _shell_less_artifact,
    _runner_ok,
    SetupFixtureBase,
)

class TestSetupFlow(SetupFixtureBase):
    """Setup readiness and host posture behavior."""

    def test_readiness_returns_checks(self):
        d = _repo(self)
        os.makedirs(os.path.join(d, ".git"))
        checks = setup_flow.readiness(d, host="claude",
                                      runner=lambda *a, **k: type("R", (), {"returncode": 1})())
        check_dict = {c[0]: (c[1], c[2]) for c in checks}
        self.assertIn("target-root", check_dict)
        self.assertTrue(check_dict["target-root"][0])

    def test_nvd_readiness_uses_target_env_and_ambient_fallback_without_secret(self):
        d = _repo(self)
        env_path = os.path.join(d, ".env")
        # Fixed synthetic value for presence/disclosure checks.
        fixture_value = "fixture-only-value"

        def row(env):
            return setup_flow._check_nvd_key(d, env)

        absent = row({})
        self.assertEqual(absent[0:2], ("nvd-api-key", None))
        self.assertIn("absent", absent[2])
        with open(env_path, "w", encoding="utf-8") as fh:
            fh.write("NVD_API_KEY=   \n")
        self.assertEqual(row({}), absent)
        with open(env_path, "w", encoding="utf-8") as fh:
            fh.write("OTHER=value\nNVD_API_KEY=" + fixture_value + "\n")
        self.assertEqual(row({}), ("nvd-api-key", None, "present"))
        os.unlink(env_path)
        self.assertEqual(row({"NVD_API_KEY": fixture_value}), ("nvd-api-key", None, "present"))

        with open(env_path, "w", encoding="utf-8") as fh:
            fh.write("NVD_API_KEY=" + fixture_value + "\n")
        original_open = open

        def unreadable(path, *args, **kwargs):
            if str(path) == env_path:
                raise PermissionError(13, "Permission denied", path)
            return original_open(path, *args, **kwargs)

        with mock.patch("builtins.open", side_effect=unreadable):
            self.assertEqual(row({}), absent)
            self.assertEqual(row({"NVD_API_KEY": fixture_value}),
                             ("nvd-api-key", None, "present"))
        for value in (absent, row({"NVD_API_KEY": fixture_value})):
            self.assertNotIn(fixture_value, repr(value))

    def test_readiness_checks_driver_roles_not_legacy(self):
        # #5.0-15: enforced-shells must verify the driver's scout/domain_panel/
        # domain_advisor shells, NOT the retired panel_review/lens_sweep.
        #
        # #1766: the PACKAGE identity here and at the three sibling sites below.
        # `setup_flow._check_host_shells` used to `import dispatch` flat, so a
        # flat `mock.patch.object(dispatch, ...)` reached it; now it imports the
        # package and only the package-qualified patch does. Both spellings
        # resolve under pytest, and the flat one silently patched a copy.
        import scripts.dispatch as dispatch
        d = _repo(self)
        with mock.patch.object(dispatch, "_is_registered", return_value=False):
            checks = setup_flow.readiness(
                d, host="claude",
                runner=lambda *a, **k: type("R", (), {"returncode": 0})())
        es = next(c for c in checks if c[0] == "enforced-shells")
        self.assertFalse(es[1])                       # unregistered -> not ok
        for role in ("scout", "domain_panel", "domain_advisor"):
            self.assertIn(role, es[2])
        self.assertNotIn("panel_review", es[2])
        self.assertNotIn("lens_sweep", es[2])

    def test_readiness_generic_host_enforced_shells_informational(self):
        # #5.0-15: the generic host runs unenforced -> informational (None), not FAIL.
        d = _repo(self)
        checks = setup_flow.readiness(
            d, host="generic",
            runner=lambda *a, **k: type("R", (), {"returncode": 0})())
        es = next(c for c in checks if c[0] == "enforced-shells")
        self.assertIsNone(es[1])

    def test_readiness_probes_carry_timeout(self):
        # #1106: every docker/codex readiness probe must be bounded.
        d = _repo(self)
        os.makedirs(os.path.join(d, ".git"))
        seen = []
        def runner(cmd, **kw):
            seen.append(kw.get("timeout"))
            return type("R", (), {"returncode": 0})()
        setup_flow.readiness(d, host="codex", runner=runner)  # docker + codex probes
        self.assertTrue(seen)
        self.assertTrue(all(t == setup_flow._PROBE_TIMEOUT for t in seen), seen)

    def test_readiness_hung_probe_is_failed_check_not_crash(self):
        # A probe that times out (or a missing binary) becomes a failed check,
        # never an unhandled exception that freezes the preflight (#1106).
        d = _repo(self)
        os.makedirs(os.path.join(d, ".git"))
        def runner(cmd, **kw):
            raise setup_flow.subprocess.TimeoutExpired(cmd, kw.get("timeout"))
        checks = {c[0]: c[1] for c in setup_flow.readiness(
            d, host="claude", runner=runner)}
        self.assertFalse(checks["docker"])

    def test_readiness_docker_ok_but_tools_image_absent(self):
        # #run7 TST-A2F: the common "Docker installed but the panopticon-tools
        # image isn't built" state (docker ok, tools-image absent) had no
        # coverage -- every prior runner returned one fixed rc for all commands.
        d = _repo(self)
        os.makedirs(os.path.join(d, ".git"))
        def runner(cmd, **kw):
            rc = 1 if cmd[:3] == ["docker", "image", "inspect"] else 0
            return type("R", (), {"returncode": rc})()
        checks = {c[0]: (c[1], c[2]) for c in setup_flow.readiness(
            d, host="generic", runner=runner)}
        self.assertTrue(checks["docker"][0])
        self.assertFalse(checks["tools-image"][0])
        self.assertIn("image absent", checks["tools-image"][1])

    def test_readiness_driver_roles_are_derived_not_shadowed(self):
        # #run7 ARC-A4C once guarded a hand-maintained shadow of
        # dispatch.ROLE_FILES against drift with a RuntimeError. #1606 removed
        # the shadow: _driver_roles IS probes.common.DRIVER_ROLES, which derives
        # from ROLE_FILES, so drift cannot happen and the trip is gone. Pinned
        # so a future "local copy" cannot quietly reintroduce the gap that
        # left `advisor` unchecked.
        import scripts.dispatch as dispatch
        self.assertIs(probes_common.DRIVER_ROLES, setup_flow._driver_roles)
        self.assertEqual(tuple(sorted(dispatch.ROLE_FILES)), setup_flow._driver_roles)

class TestReadinessCannotAssertWhatItDidNotCheck(unittest.TestCase):
    """#1344 F2: P2/P3 cease to be expressible."""

    def setUp(self):
        _isolate_codex_probes(self)

    def _check(self, host):
        # #1599: the posture probe is mocked and a real tree is named. This
        # used to reach `host_probes.run_probes` with repo_root=None, which
        # read ~/.claude/agents and ~/.codex/agents on whatever machine ran
        # the suite -- these assertions are about the REGISTRY, not about the
        # developer's home directory.
        with mock.patch.object(host_probes, "run_probes",
                               return_value=_shell_less_artifact(host)):
            return dict((name, (ok, detail))
                        for name, ok, detail in
                        setup_flow._check_host_shells(host, lambda *a, **k: None,
                                                      "."))

    def test_codex_no_longer_claims_enforcement_it_never_verified(self):
        # #1344 F2: pin this against real registration state, not whatever
        # happens to be under ~/.codex/agents on the machine running the
        # suite -- a developer box that has ever run `--emit-host-agents
        # codex` for real would otherwise make `ok` legitimately True and
        # the assertion below flaky-by-environment rather than a check on
        # the code.
        import scripts.dispatch as dispatch
        with mock.patch.object(dispatch, "_is_registered", return_value=False):
            ok, detail = self._check("codex")["enforced-shells"]
        self.assertIsNot(ok, True,
                         "readiness asserted enforcement without checking it")
        self.assertNotIn("codex_exec", detail,
                         "codex_exec was removed; readiness must not cite it")

    def test_codex_reports_enforced_when_its_shells_really_are_registered(self):
        # The other half of test_codex_no_longer_claims_enforcement_it_never
        # _verified. That one proves the hardcoded True is gone; this one
        # proves a REAL True still arrives, so "derived from a check" is
        # demonstrated in both directions rather than asserted in a docstring.
        import scripts.dispatch as dispatch
        with mock.patch.object(dispatch, "_is_registered", return_value=True):
            ok, detail = self._check("codex")["enforced-shells"]
        self.assertTrue(ok)
        self.assertNotIn("codex_exec", detail)

    def test_gemini_is_not_told_to_run_a_command_that_raises(self):
        ok, detail = self._check("gemini")["enforced-shells"]
        self.assertNotIn("--emit-host-agents gemini", detail)
        self.assertIsNot(ok, True)

    def test_a_host_that_registers_no_shells_says_so_honestly(self):
        for name in ("gemini", "generic"):
            with self.subTest(host=name):
                ok, detail = self._check(name)["enforced-shells"]
                self.assertIsNone(ok, "not-applicable is None, not False")
                self.assertIn("registers no", detail)

    def test_claude_still_reports_its_shells(self):
        # The one host with real shells must keep the check it already had.
        result = self._check("claude")
        self.assertIn("enforced-shells", result)

    def test_codex_still_reports_whether_the_cli_is_there(self):
        # The one honest check in the old codex branch. It must survive the
        # rewrite that deletes the dishonest one next to it.
        calls = []

        def runner(cmd, **kwargs):
            calls.append(cmd)
            raise OSError("not installed")

        # #1599: mocked, and given a tree. Unmocked this reached the live
        # Codex probes and read the home directory of whoever ran the suite;
        # the subject here is the `codex --version` call recorded in `calls`.
        with mock.patch.object(host_probes, "run_probes",
                               return_value=_shell_less_artifact("codex")):
            result = dict((name, (ok, detail)) for name, ok, detail
                          in setup_flow._check_host_shells("codex", runner, "."))
        self.assertIn(["codex", "--version"], calls,
                      "readiness stopped probing for the Codex CLI")
        ok, detail = result["codex-cli"]
        self.assertFalse(ok)
        self.assertIn("Codex CLI unavailable", detail)

class TestReadinessProbesThePostureAndNamesTheFix(unittest.TestCase):
    """#1344 F3b Task 6, surface 4 (spec 5.1). `driver setup` has no run
    directory, so there is no artifact to read -- readiness must probe. All
    assertions here go through host_disclosure's own constants/behaviour
    rather than hand-rolled substrings, per the plan's standing rule: "NOT
    PROVEN" contains "PROVEN" as a substring, so a bare `assertIn("PROVEN",
    ...)` cannot tell the all-proven case from a 1-of-5 NOT-PROVEN case."""

    def test_readiness_reports_every_unproven_capability_with_its_remedy(self):
        with mock.patch.object(host_probes, "run_probes",
                               return_value=_mixed_artifact("claude")):
            checks = setup_flow._check_host_shells("claude", _runner_ok, ".")
        named = {c[0]: c for c in checks}
        refuted = named["host-capability:" + hosts.TOOL_POLICY_ENFORCED]
        self.assertIs(False, refuted[1])
        self.assertIn("shadow-shell-scan", refuted[2])
        self.assertIn("fix:", refuted[2])
        unknown = named["host-capability:" + hosts.USAGE_LEDGER]
        self.assertIsNone(unknown[1], "unknown is NOT APPLICABLE, not failed")

    def test_a_proven_capability_gets_no_readiness_row(self):
        with mock.patch.object(host_probes, "run_probes",
                               return_value=_mixed_artifact("claude")):
            checks = setup_flow._check_host_shells("claude", _runner_ok, ".")
        self.assertNotIn("host-capability:" + hosts.ARTIFACT_WRITE_GUARD,
                         [c[0] for c in checks])

    def test_an_all_proven_host_says_so_rather_than_reporting_nothing(self):
        # 5.1's inverse: absence of warnings must mean "measured and proven",
        # never "nobody looked". The synthetic fixture pins the shape; claude
        # proves this capability since plan 5, other hosts do not claim it
        # -- test_host_disclosure.py's TestTheInverseCarriesEqualWeight
        # hits the identical trap and resolves it the same way: patch a real
        # host's claims to all five rather than asserting something the real
        # registry cannot produce. Claude's claims are patched (not a wholly
        # synthetic host name) so shell_format/registration_dir stay real and
        # _check_host_shells still reaches the probing code -- a synthetic
        # HostSpec with no shell_format would return from the enforced-shells
        # branch before ever getting there, proving nothing about this
        # surface.
        assert setup_flow.hosts is hosts, (
            "setup_flow's hosts import has drifted from the canonical "
            "scripts.hosts module -- patching hosts.HOSTS below would be a "
            "silent no-op")
        claiming = dataclasses.replace(hosts.HOSTS["claude"],
                                       claims=frozenset(hosts.CAPABILITIES))
        with mock.patch.dict(hosts.HOSTS, {"claude": claiming}), \
                mock.patch.object(host_probes, "run_probes",
                                  return_value=_all_proven_artifact("claude")):
            checks = setup_flow._check_host_shells("claude", _runner_ok, ".")
        row = {c[0]: c for c in checks}["host-capabilities"]
        self.assertIs(True, row[1])
        self.assertEqual(host_disclosure.ALL_PROVEN, row[2])

    def test_an_operational_note_does_not_downgrade_an_all_proven_row(self):
        # N2: readiness reads `head == ALL_PROVEN` as its PASS. An operational
        # fact appended to the capability lines made `head` something else on
        # every headless run whose CLI lacks --json-schema, so a fully proven
        # host reported WARN for a flag that gates nothing.
        artifact = dict(_all_proven_artifact("claude"))
        artifact[hosts.CLI_FLAGS] = {
            hosts.OUTPUT_SCHEMA: {"flag": "--json-schema", "advertised": False,
                                  "detail": "`claude --help` does not advertise it"}}
        claiming = dataclasses.replace(hosts.HOSTS["claude"],
                                       claims=frozenset(hosts.CAPABILITIES))
        with mock.patch.dict(hosts.HOSTS, {"claude": claiming}), \
                mock.patch.object(host_probes, "run_probes", return_value=artifact):
            checks = setup_flow._check_host_shells("claude", _runner_ok, ".")
        row = {c[0]: c for c in checks}["host-capabilities"]
        self.assertIs(True, row[1])
        self.assertEqual(host_disclosure.ALL_PROVEN, row[2])

    def test_a_probe_failure_does_not_crash_readiness(self):
        # Readiness must survive a probe that raises; a setup command that
        # tracebacks tells the operator nothing about what to fix.
        with mock.patch.object(host_probes, "run_probes",
                               side_effect=OSError("boom")):
            checks = setup_flow._check_host_shells("claude", _runner_ok, ".")
        row = {c[0]: c for c in checks}["host-capabilities"]
        self.assertIsNone(row[1])
        self.assertIn("could not be probed", row[2])

class TestReadinessNeverReadsAnUnreadableEnvelopeAsProof(unittest.TestCase):
    """`host_disclosure.lines()` returns [] for TWO different reasons -- every
    capability is proven, AND the envelope is unreadable (`caps is None or host
    is None`). Readiness collapsed them into one `ok=True, ALL_PROVEN` row,
    which is precisely what `headline()`'s docstring says must never happen:
    "an empty result from a missing artifact would render as the all-proven
    case and turn 5.1's guarantee inside out". It also rendered as a PASSING
    readiness check rather than a limitation.

    Readiness reads the module's three-outcome contract instead of re-deriving
    a two-outcome one from `lines()`.
    """

    BAD = {
        "host is not a string": {"host": None, "capabilities": {
            hosts.TOOL_POLICY_ENFORCED: {"state": hosts.REFUTED,
                                         "by": "shadow-shell-scan",
                                         "detail": "ships panopticon-scout.md"}}},
        "capabilities is not a mapping": {"host": "claude",
                                          "capabilities": "garbage"},
        "the artifact is not a dict at all": "not-a-dict",
        "the artifact is empty": {},
    }

    def test_an_unreadable_envelope_reports_no_evidence_not_all_proven(self):
        for name, bad in self.BAD.items():
            with self.subTest(envelope=name):
                with mock.patch.object(host_probes, "run_probes",
                                       return_value=bad):
                    checks = setup_flow._check_host_shells("claude", _runner_ok, ".")
                row = {c[0]: c for c in checks}["host-capabilities"]
                # By EQUALITY against the module's own constants: "1 of 5 NOT
                # PROVEN" contains "PROVEN", so no substring test here can tell
                # the two apart.
                self.assertEqual(("host-capabilities", None,
                                  host_disclosure.NO_EVIDENCE), row)

    def test_no_evidence_emits_no_per_capability_rows(self):
        # Nothing was measured, so there is no per-capability verdict to
        # report. Five rows whose detail is a bare capability name would be
        # "unenforced alone" -- a mood, not a disclosure (5.1).
        with mock.patch.object(host_probes, "run_probes", return_value={}):
            checks = setup_flow._check_host_shells("claude", _runner_ok, ".")
        self.assertEqual([], [c for c in checks
                              if c[0].startswith("host-capability:")])

class TestShellLessHostsGetTheWholeDisclosure(unittest.TestCase):
    """`gemini` and `generic` are the two registry rows that claim NOTHING and
    register no shells, so five-of-five-unproven is their entire story -- and
    the `enforced-shells` early return handed them one line that named the
    host and no capability, no probe and no remedy. 5.1 names no exemption for
    shell-less hosts.

    Both rows are still exercised after gemini left the selectable set (#1621,
    2026-09-13): `_check_host_shells` reads the REGISTRY, which still knows
    gemini, and the disclosure it owes a shell-less host is a fact about the
    row rather than about whether `--host` will accept the name.
    """

    def _rows(self, host):
        with mock.patch.object(host_probes, "run_probes",
                               return_value=_shell_less_artifact(host)):
            return dict((c[0], c) for c in
                        setup_flow._check_host_shells(host, _runner_ok, "."))

    def test_the_enforced_shells_row_it_already_had_survives(self):
        for host in ("gemini", "generic"):
            with self.subTest(host=host):
                row = self._rows(host)["enforced-shells"]
                self.assertIsNone(row[1])
                self.assertIn("registers no", row[2])

    def test_it_gets_a_headline_and_a_row_per_capability_with_the_remedy(self):
        for host in ("gemini", "generic"):
            with self.subTest(host=host):
                rows = self._rows(host)
                head = rows["host-capabilities"]
                self.assertIsNone(head[1])
                self.assertNotEqual(host_disclosure.ALL_PROVEN, head[2])
                self.assertNotEqual(host_disclosure.NO_EVIDENCE, head[2])
                for capability in hosts.CAPABILITIES:
                    with self.subTest(capability=capability):
                        row = rows["host-capability:" + capability]
                        self.assertIn(capability, row[2])
                        self.assertIn(host, row[2])
                        # the remedy VERBATIM, per capability -- five distinct
                        # strings, so a surface that rendered one of them for
                        # all five fails here.
                        self.assertIn(host_disclosure.remedy(capability, host),
                                      row[2])

class TestReadinessDoesNotSwallowTheLaunchGuard(unittest.TestCase):
    """N-M3: readiness's `except Exception` around run_probes turned the
    suite's no-live-launch refusal into a benign "posture could not be probed"
    row. That is exactly the failure I-5 exists to remove, on exactly the path
    that forced `_isolate_codex_probes` to exist -- readiness reaches a live
    Codex probe. Latent today, because nothing in the suite gets that far;
    structural, because the guarantee has to hold for the test nobody has
    written yet."""

    @staticmethod
    def _runner(cmd, **kw):
        """readiness also probes `codex --version`; that must never be the
        real binary (the guardrails' "suite never launches a host binary",
        which a PATH-shim run catches). Every readiness call here injects it.
        """
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    def test_readiness_with_no_injected_runner_cannot_reach_the_real_cli(self):
        """N-M3 round 2 fixed the two tests below by injecting a runner. That
        is discipline, and discipline is what failed here: readiness probes
        `codex --version` through a runner bound as a DEFAULT ARGUMENT, so the
        autouse guard could not reach it and the NEXT test to forget would
        launch the real binary and stay green. With the launcher read from a
        module attribute, forgetting is now loud.
        """
        from scripts import codex_host
        d = _repo(self)
        with self.assertRaises(codex_host.LaunchRefused):
            setup_flow.readiness(d, host="codex")

    def test_a_refused_live_launch_escapes_readiness(self):
        from scripts import codex_host
        d = _repo(self)
        with mock.patch.object(
                host_probes, "run_probes",
                side_effect=codex_host.LaunchRefused("test tried to launch the real codex CLI")):
            with self.assertRaises(codex_host.LaunchRefused):
                setup_flow.readiness(d, host="codex", runner=self._runner)

    def test_every_other_probe_failure_is_still_a_readiness_row(self):
        d = _repo(self)
        with mock.patch.object(host_probes, "run_probes",
                               side_effect=RuntimeError("probe exploded")):
            rows = setup_flow.readiness(d, host="codex", runner=self._runner)
        posture = dict((name, detail) for name, _ok, detail in rows)
        self.assertIn("host-capabilities", posture)
        self.assertIn("probe exploded", posture["host-capabilities"])

class TestReadinessWithoutATreeSaysWhatIsMissing(unittest.TestCase):
    """#1598: called without `repo_root`, `_check_host_shells` handed the
    argument straight to `host_probes.run_probes` as `review_root`, where
    `probe_shadow_shells` joined it with a relative path and raised. The
    try/except turned that into an honest-but-useless readiness row:

        ('host-capabilities', None, "posture could not be probed: expected
         str, bytes or os.PathLike object, not NoneType")

    Non-gating and true, and no operator can act on it. An internal type
    error is not a remedy (spec 5.1: "name the capability, the host, the
    probe, and the remedy").

    #1599 is the same defect seen from the tests' side: reaching
    `run_probes` at all made two unit tests depend on whatever
    `~/.claude/agents` holds on the machine running the suite.
    """

    def _rows(self, host="claude"):
        probe = mock.patch.object(
            host_probes, "run_probes",
            side_effect=AssertionError("readiness probed with no tree to probe"))
        with probe as spy:
            checks = setup_flow._check_host_shells(host, _runner_ok)  # repo-root-exempt: the subject
        return spy, {c[0]: c for c in checks}

    def test_the_row_names_the_missing_argument_not_a_typeerror(self):
        _spy, rows = self._rows()
        _name, ok, detail = rows["host-capabilities"]
        self.assertIsNone(ok, "a caller's omission is not a host fault")
        self.assertIn("repo_root", detail)
        self.assertNotIn("NoneType", detail)
        self.assertNotIn("os.PathLike", detail)

    def test_no_probe_runs_when_there_is_nothing_to_probe(self):
        # #1599's root cause. The probes read `~/.claude/agents`,
        # `~/.codex/agents` and `.claude/settings.local.json`; a unit test that
        # supplied no tree was measuring the developer's home directory.
        spy, _rows = self._rows()
        spy.assert_not_called()

    def test_the_checks_it_can_still_make_survive(self):
        # Not a bare refusal: `enforced-shells` needs no tree, so it is still
        # reported. Only the posture row -- the one that needs a tree -- says
        # it could not be established.
        _spy, rows = self._rows()
        self.assertIn("enforced-shells", rows)
        self.assertEqual([], [n for n in rows if n.startswith("host-capability:")],
                         "no per-capability verdict may be invented from no probe")

