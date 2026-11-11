"""Setup readiness and host posture behavior."""

import dataclasses
import inspect
import os
import unittest
from unittest import mock


import scripts.host_disclosure as host_disclosure
import scripts.hosts as hosts
import scripts.probes.common as probes_common
import scripts.setup_preflight as setup_preflight


from tests.setup_helpers import (
    _repo,
    _mixed_artifact,
    _all_proven_artifact,
    _shell_less_artifact,
    _runner_ok,
    SetupFixtureBase,
)


class TestReadinessRequiresTheEstablishedEnvelope(unittest.TestCase):
    """#3535: readiness renders the posture this invocation already measured."""

    def test_both_entry_points_require_the_envelope(self):
        shells = inspect.signature(setup_preflight._check_host_shells).parameters
        self.assertIs(inspect.Parameter.empty, shells["repo_root"].default)
        self.assertIs(inspect.Parameter.empty, shells["envelope"].default)

        readiness = inspect.signature(setup_preflight.setup_readiness).parameters
        self.assertEqual(inspect.Parameter.KEYWORD_ONLY, readiness["envelope"].kind)
        self.assertIs(inspect.Parameter.empty, readiness["envelope"].default)

class TestSetupFlow(SetupFixtureBase):
    """Setup readiness and host posture behavior."""

    def test_readiness_returns_checks(self):
        d = _repo(self)
        os.makedirs(os.path.join(d, ".git"))
        checks = setup_preflight.readiness(d, host="claude",
                                      runner=lambda *a, **k: type("R", (), {"returncode": 1})(),
                                      envelope=_shell_less_artifact("claude"))
        check_dict = {c[0]: (c[1], c[2]) for c in checks}
        self.assertIn("target-root", check_dict)
        self.assertTrue(check_dict["target-root"][0])

    def test_nvd_readiness_uses_target_env_and_ambient_fallback_without_secret(self):
        d = _repo(self)
        env_path = os.path.join(d, ".env")
        # Fixed synthetic value for presence/disclosure checks.
        fixture_value = "fixture-only-value"

        def row(env):
            return setup_preflight._check_nvd_key(d, env)

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
        # `setup_preflight._check_host_shells` used to `import dispatch` flat, so a
        # flat `mock.patch.object(dispatch, ...)` reached it; now it imports the
        # package and only the package-qualified patch does. Both spellings
        # resolve under pytest, and the flat one silently patched a copy.
        import scripts.dispatch as dispatch
        d = _repo(self)
        with mock.patch.object(dispatch, "_is_registered", return_value=False):
            checks = setup_preflight.readiness(
                d, host="claude",
                runner=lambda *a, **k: type("R", (), {"returncode": 0})(),
                envelope=_shell_less_artifact("claude"))
        es = next(c for c in checks if c[0] == "enforced-shells")
        self.assertFalse(es[1])                       # unregistered -> not ok
        for role in ("scout", "domain_panel", "domain_advisor"):
            self.assertIn(role, es[2])
        self.assertNotIn("panel_review", es[2])
        self.assertNotIn("lens_sweep", es[2])

    def test_readiness_generic_host_enforced_shells_informational(self):
        # #5.0-15: the generic host runs unenforced -> informational (None), not FAIL.
        d = _repo(self)
        checks = setup_preflight.readiness(
            d, host="generic",
            runner=lambda *a, **k: type("R", (), {"returncode": 0})(),
            envelope=_shell_less_artifact("generic"))
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
        setup_preflight.readiness(
            d, host="codex", runner=runner,
            envelope=_shell_less_artifact("codex"))  # docker + codex probes
        self.assertTrue(seen)
        self.assertTrue(all(t == setup_preflight._PROBE_TIMEOUT for t in seen), seen)

    def test_readiness_hung_probe_is_failed_check_not_crash(self):
        # A probe that times out (or a missing binary) becomes a failed check,
        # never an unhandled exception that freezes the preflight (#1106).
        d = _repo(self)
        os.makedirs(os.path.join(d, ".git"))
        def runner(cmd, **kw):
            raise setup_preflight.subprocess.TimeoutExpired(cmd, kw.get("timeout"))
        checks = {c[0]: c[1] for c in setup_preflight.readiness(
            d, host="claude", runner=runner,
            envelope=_shell_less_artifact("claude"))}
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
        checks = {c[0]: (c[1], c[2]) for c in setup_preflight.readiness(
            d, host="generic", runner=runner,
            envelope=_shell_less_artifact("generic"))}
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
        self.assertIs(probes_common.DRIVER_ROLES, setup_preflight._driver_roles)
        self.assertEqual(tuple(sorted(dispatch.ROLE_FILES)), setup_preflight._driver_roles)

class TestReadinessCannotAssertWhatItDidNotCheck(unittest.TestCase):
    """#1344 F2: P2/P3 cease to be expressible."""

    def _check(self, host):
        return dict((name, (ok, detail))
                    for name, ok, detail in
                    setup_preflight._check_host_shells(
                        host, lambda *a, **k: None, ".",
                        _shell_less_artifact(host)))

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

    def test_generic_is_not_told_to_run_a_command_that_raises(self):
        # #3494 restored gemini with TOML policy shells (after its #1621
        # retirement); generic remains the shell-less row.
        ok, detail = self._check("generic")["enforced-shells"]
        self.assertNotIn("--emit-host-agents generic", detail)
        self.assertIsNot(ok, True)

    def test_a_host_that_registers_no_shells_says_so_honestly(self):
        for name in ("generic",):
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

        result = dict((name, (ok, detail)) for name, ok, detail
                      in setup_preflight._check_host_shells(
                          "codex", runner, ".", _shell_less_artifact("codex")))
        self.assertIn(["codex", "--version"], calls,
                      "readiness stopped probing for the Codex CLI")
        ok, detail = result["codex-cli"]
        self.assertFalse(ok)
        self.assertIn("Codex CLI unavailable", detail)

class TestReadinessRendersThePostureAndNamesTheFix(unittest.TestCase):
    """#1344 F3b Task 6, surface 4 (spec 5.1). Readiness receives the
    invocation's established envelope and renders it. All
    assertions here go through host_disclosure's own constants/behaviour
    rather than hand-rolled substrings, per the plan's standing rule: "NOT
    PROVEN" contains "PROVEN" as a substring, so a bare `assertIn("PROVEN",
    ...)` cannot tell the all-proven case from a 1-of-5 NOT-PROVEN case."""

    def test_readiness_reports_every_unproven_capability_with_its_remedy(self):
        checks = setup_preflight._check_host_shells(
            "claude", _runner_ok, ".", _mixed_artifact("claude"))
        named = {c[0]: c for c in checks}
        refuted = named["host-capability:" + hosts.TOOL_POLICY_ENFORCED]
        self.assertIs(False, refuted[1])
        self.assertIn("shadow-shell-scan", refuted[2])
        self.assertIn("fix:", refuted[2])
        unknown = named["host-capability:" + hosts.USAGE_LEDGER]
        self.assertIsNone(unknown[1], "unknown is NOT APPLICABLE, not failed")

    def test_a_proven_capability_gets_no_readiness_row(self):
        checks = setup_preflight._check_host_shells(
            "claude", _runner_ok, ".", _mixed_artifact("claude"))
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
        assert setup_preflight.hosts is hosts, (
            "setup_flow's hosts import has drifted from the canonical "
            "scripts.hosts module -- patching hosts.HOSTS below would be a "
            "silent no-op")
        claiming = dataclasses.replace(hosts.HOSTS["claude"],
                                       claims=frozenset(hosts.CAPABILITIES))
        with mock.patch.dict(hosts.HOSTS, {"claude": claiming}):
            checks = setup_preflight._check_host_shells(
                "claude", _runner_ok, ".", _all_proven_artifact("claude"))
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
        with mock.patch.dict(hosts.HOSTS, {"claude": claiming}):
            checks = setup_preflight._check_host_shells(
                "claude", _runner_ok, ".", artifact)
        row = {c[0]: c for c in checks}["host-capabilities"]
        self.assertIs(True, row[1])
        self.assertEqual(host_disclosure.ALL_PROVEN, row[2])

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
                checks = setup_preflight._check_host_shells(
                    "claude", _runner_ok, ".", bad)
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
        checks = setup_preflight._check_host_shells("claude", _runner_ok, ".", {})
        self.assertEqual([], [c for c in checks
                              if c[0].startswith("host-capability:")])

class TestShellLessHostsGetTheWholeDisclosure(unittest.TestCase):
    """`generic` is the registry row that claims NOTHING and registers no
    shells (#3494 restored `gemini` as a 5/5 host with TOML policy shells after
    its #1621 retirement), so five-of-five-unproven is its entire story -- and
    the `enforced-shells` early return handed it one line that named the
    host and no capability, no probe and no remedy. 5.1 names no exemption for
    shell-less hosts.
    """

    def _rows(self, host):
        return dict((c[0], c) for c in setup_preflight._check_host_shells(
            host, _runner_ok, ".", _shell_less_artifact(host)))

    def test_the_enforced_shells_row_it_already_had_survives(self):
        for host in ("generic",):
            with self.subTest(host=host):
                row = self._rows(host)["enforced-shells"]
                self.assertIsNone(row[1])
                self.assertIn("registers no", row[2])

    def test_it_gets_a_headline_and_a_row_per_capability_with_the_remedy(self):
        for host in ("generic",):
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

