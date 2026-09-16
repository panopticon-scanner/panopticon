import copy
import json
import os
from unittest import mock

import pytest

from scripts import dispatch, host_probes, hosts
import scripts.probes.claude as claude_probes
import scripts.probes.codex as codex_probes
import scripts.probes.common as probes_common


def surfaces():
    surface = {
        "tools": ["mcp__panopticon_scope__read_file", "mcp__panopticon_scope__search",
                  "mcp__panopticon_scope__list_files", "list_mcp_resources",
                  "list_mcp_resource_templates", "read_mcp_resource"],
        "direct_tools": ["functions.exec", "functions.wait", "functions.request_user_input"],
        "forbidden": dict.fromkeys(("exec", "patch", "spawn", "fetch", "process", "require"), "undefined"),
        # Third read (#1642): the hard link planted INSIDE the directory grant.
        # The wording is the broker's own, because that is what the probe reads.
        "reads": [{"isError": False, "content": [{"type": "text", "text": "inside fixture"}]},
                  {"isError": True, "content": [{"type": "text", "text": "outside this entry scope"}]},
                  {"isError": True, "content": [{"type": "text", "text": "Read tool refused: read scope "
                    "denies a hard-linked file inside a directory grant (st_nlink=2)"}]}],
    }
    return [(role + ".toml", copy.deepcopy(surface)) for role in (*probes_common.DRIVER_ROLES, "setup-scan")]


@pytest.mark.parametrize("probe,probe_id", [
    (codex_probes.probe_codex_tool_policy, codex_probes.CODEX_EFFECTIVE_TOOLS),
    (codex_probes.probe_codex_read_scope, codex_probes.CODEX_READ_SCOPE),
])
def test_every_claim_requires_measured_headless_surface(probe, probe_id, tmp_path):
    measure = mock.Mock(return_value=surfaces())
    state, by, detail = probe("codex", settings_path=str(tmp_path / "settings.json"), measure=measure)
    assert state == hosts.PROVEN
    assert by == probe_id
    assert "scout.toml" in detail
    measure.assert_called_once_with()
    measure.reset_mock()
    assert probe("codex", measure=measure)[0] == hosts.UNKNOWN
    measure.assert_not_called()


@pytest.mark.parametrize("change", [
    lambda s: s["tools"].append("exec_command"),
    lambda s: s["tools"].append("apply_patch"),
    lambda s: s["tools"].remove("mcp__panopticon_scope__read_file"),
    lambda s: s["direct_tools"].append("web.run"),
    lambda s: s["forbidden"].update(fetch="function"),
    lambda s: s["forbidden"].pop("require"),
])
def test_native_tool_policy_mutation_refutes_both_security_claims(change, tmp_path):
    measured = surfaces()
    change(measured[-1][1])
    for probe in (codex_probes.probe_codex_tool_policy, codex_probes.probe_codex_read_scope):
        state, _by, detail = probe("codex", settings_path=str(tmp_path / "settings.json"),
                                  measure=lambda: measured)
        assert state == hosts.REFUTED
        assert measured[-1][0] in detail


def test_widened_scope_mutation_refutes_actual_read_boundary(tmp_path):
    measured = surfaces()
    measured[0][1]["reads"][1] = {"isError": False, "content": [{"type": "text", "text": "outside read allowed"}]}
    state, by, detail = codex_probes.probe_codex_read_scope(
        "codex", settings_path=str(tmp_path / "settings.json"), measure=lambda: measured)
    assert state == hosts.REFUTED
    assert by == codex_probes.CODEX_READ_SCOPE
    assert "deny failed" in detail


def test_a_readable_hard_link_inside_a_directory_grant_refutes_the_claim(tmp_path):
    # #1642: the boundary this row claims is not "a path outside the grant is
    # denied" but "nothing outside the grant is readable THROUGH it". A hard
    # link is the case where those two differ, so the probe plants one.
    measured = surfaces()
    measured[-1][1]["reads"][2] = {"isError": False, "content": [
        {"type": "text", "text": "private outside content"}]}
    state, by, detail = codex_probes.probe_codex_read_scope(
        "codex", settings_path=str(tmp_path / "settings.json"), measure=lambda: measured)
    assert state == hosts.REFUTED
    assert by == codex_probes.CODEX_READ_SCOPE
    assert "hard link" in detail and measured[-1][0] in detail


def test_a_hard_link_denied_for_some_other_reason_refutes_too(tmp_path):
    # Every role but setup-scan holds FILE grants, where the planted link is
    # denied for being outside the scope at all -- a denial that proves nothing
    # about the rule. The probe therefore requires that the one role with a
    # DIRECTORY grant refused it BY the hard-link rule; a build where the rule
    # is gone denies every read for the old reason and must not read as proven.
    measured = surfaces()
    for _path, surface in measured:
        surface["reads"][2] = {"isError": True, "content": [
            {"type": "text", "text": "Read tool refused: Denied: /x is outside this entry's read scope"}]}
    state, _by, detail = codex_probes.probe_codex_read_scope(
        "codex", settings_path=str(tmp_path / "settings.json"), measure=lambda: measured)
    assert state == hosts.REFUTED
    assert "hard-link" in detail


def test_a_two_read_measurement_is_unknown_not_proven(tmp_path):
    measured = surfaces()
    for _path, surface in measured:
        surface["reads"] = surface["reads"][:2]
    state, _by, detail = codex_probes.probe_codex_read_scope(
        "codex", settings_path=str(tmp_path / "settings.json"), measure=lambda: measured)
    assert state == hosts.UNKNOWN
    assert "three-read" in detail


@pytest.mark.parametrize("probe", [codex_probes.probe_codex_tool_policy, codex_probes.probe_codex_read_scope])
def test_unavailable_runtime_is_unknown_with_reason(probe, tmp_path):
    state, _by, detail = probe("codex", settings_path=str(tmp_path / "settings.json"),
                               measure=mock.Mock(side_effect=FileNotFoundError("codex not installed")))
    assert state == hosts.UNKNOWN
    assert "codex not installed" in detail
    assert probe("codex", settings_path=str(tmp_path / "settings.json"), measure=lambda: [])[0] == hosts.UNKNOWN


def test_missing_shell_is_refuted_without_invoking_runtime(tmp_path):
    with mock.patch("scripts.codex_host.inspect_surface", side_effect=AssertionError("no launch")) as inspector:
        state, _by, detail = codex_probes.probe_codex_tool_policy(
            "codex", registration_dir=str(tmp_path), settings_path=str(tmp_path / "settings.json"))
    assert state == hosts.REFUTED
    assert "reviewer shell is missing" in detail
    inspector.assert_not_called()


def test_probe_fixture_uses_real_emitter_but_injects_all_runtime_work(tmp_path):
    registered = tmp_path / "registered"
    dispatch.emit_host_agents("codex", str(registered))
    seen = []

    def inspect(entry, env, root, run_dir, **kwargs):
        with open(env["PANOPTICON_READ_SCOPE"], encoding="utf-8") as stream:
            assert json.load(stream) == {entry["id"]: entry["scope"]}
        inside, outside, linked = kwargs["probe_paths"]
        # #1642: a REAL hard link inside the directory grant, naming the file
        # outside it -- the fixture the refutation row rests on.
        assert os.path.dirname(linked) == os.path.dirname(inside)
        assert os.path.samefile(linked, outside) and os.stat(linked).st_nlink == 2
        if entry["id"] == "setup-scan":
            assert entry["scope"] == {"files": [], "dirs": [root], "reads": []}
            assert entry["model"] is None
        else:
            assert entry["scope"]["files"] == [inside]
            assert root == run_dir
        assert outside not in entry["scope"]["files"]
        assert linked not in entry["scope"]["files"]
        assert env["PANOPTICON_ENTRY_ID"] == entry["id"]
        assert kwargs["registration_dir"] == str(registered)
        seen.append(entry["agent"])
        return surfaces()[0][1]

    measured = codex_probes._codex_surfaces(str(registered), inspector=inspect)
    assert len(measured) == len(probes_common.DRIVER_ROLES) + 1
    assert len(set(seen)) == len(probes_common.DRIVER_ROLES) + 1


def test_an_unplantable_hard_link_fixture_only_unproves_the_read_scope_row(tmp_path):
    # Fix round 1 (F3): the fixture belongs to ONE row. `_codex_surfaces` used
    # to RAISE when os.link failed, and the measurement is shared by both codex
    # probes -- so a filesystem with no links to plant also un-proved
    # codex-effective-tools, a claim about the effective V8 surface that has
    # nothing to do with hard links (and `hosts.py`: UNKNOWN gates as REFUTED).
    # Nothing was cached on that path either, so the whole inspection ran twice.
    registered = tmp_path / "registered"
    dispatch.emit_host_agents("codex", str(registered))
    seen = []

    def inspect(entry, env, root, run_dir, **kwargs):
        seen.append(kwargs["probe_paths"])
        return copy.deepcopy(surfaces()[0][1])

    with mock.patch.object(os, "link", side_effect=OSError("cross-device link")), \
            mock.patch.object(probes_common, "probe_cli_flags", return_value={}), \
            mock.patch("scripts.codex_host.inspect_surface", inspect):
        artifact = host_probes.run_probes("codex", str(tmp_path), registration_dir=str(registered),
                                          settings_path=str(tmp_path / "settings.json"))
    assert artifact["capabilities"][hosts.TOOL_POLICY_ENFORCED]["state"] == hosts.PROVEN
    read_row = artifact["capabilities"][hosts.READ_SCOPE_CONFINED]
    assert read_row["state"] == hosts.UNKNOWN
    assert "cross-device link" in read_row["detail"]
    # Measured ONCE for both probes, and with no probe paths at all: a
    # two-read measurement must not stand in for the three-read one.
    assert seen == [None] * (len(probes_common.DRIVER_ROLES) + 1)


def test_registry_dispatch_shares_measurement_only_within_one_invocation(tmp_path):
    # `probe_cli_flags` reads `codex exec --help` on every headless run (D10
    # N1) and is tested in tests/probes/test_common.py; stubbed here so this
    # test measures the registry's sharing rule rather than the machine's PATH.
    with mock.patch.object(probes_common, "probe_cli_flags", return_value={}), \
            mock.patch.object(codex_probes, "_codex_surfaces", side_effect=lambda _registration: surfaces()) as measure:
        for _ in range(2):
            artifact = host_probes.run_probes("codex", str(tmp_path), registration_dir=str(tmp_path),
                                              settings_path=str(tmp_path / "settings.json"))
            for capability in (hosts.TOOL_POLICY_ENFORCED, hosts.READ_SCOPE_CONFINED):
                assert artifact["capabilities"][capability]["state"] == hosts.PROVEN
        assert measure.call_count == 2


def test_the_probe_never_swallows_the_suites_launch_guard(tmp_path):
    # I-5: _codex_measure maps any exception to UNKNOWN, so a test that reached
    # a live `codex` and failed would still read as a clean "unavailable".
    from scripts import codex_host

    for probe in (codex_probes.probe_codex_tool_policy, codex_probes.probe_codex_read_scope):
        with pytest.raises(codex_host.LaunchRefused):
            probe("codex", settings_path=str(tmp_path / "settings.json"),
                  measure=mock.Mock(side_effect=codex_host.LaunchRefused("refused")))


def test_the_bundled_catalog_is_dumped_once_per_probe_run(tmp_path):
    # I-6: _catalog() ran inside command(), so the probe launched `codex debug
    # models --bundled` once PER ROLE -- five per run_probes, and driver loop
    # probes on every iteration.
    import json as _json
    from types import SimpleNamespace

    registered = tmp_path / "registered"
    dispatch.emit_host_agents("codex", str(registered))
    calls = []

    def runner(argv, **kwargs):
        calls.append(list(argv))
        return SimpleNamespace(returncode=0, stderr="",
                               stdout=_json.dumps({"models": [{"slug": "m"}]}))

    def inspect(entry, env, root, run_dir, **kwargs):
        kwargs["catalog"]()          # what command() does on the real path
        return surfaces()[0][1]

    measured = codex_probes._codex_surfaces(str(registered), inspector=inspect, runner=runner)
    assert len(measured) == len(probes_common.DRIVER_ROLES) + 1
    assert calls == [["codex", "debug", "models", "--bundled"]]


def test_the_role_inspections_run_concurrently(tmp_path):
    import threading

    registered = tmp_path / "registered"
    dispatch.emit_host_agents("codex", str(registered))
    barrier = threading.Barrier(len(probes_common.DRIVER_ROLES) + 1, timeout=20)

    def inspect(entry, env, root, run_dir, **kwargs):
        barrier.wait()               # sequential inspection cannot get here
        return surfaces()[0][1]

    measured = codex_probes._codex_surfaces(str(registered), inspector=inspect,
                                           runner=mock.Mock())
    assert len(measured) == len(probes_common.DRIVER_ROLES) + 1


def test_claudes_read_guard_probe_stays_unknown_for_a_row_that_does_not_map_it(tmp_path):
    # M-11: codex now DECLARES read_scope_confined, so this probe's
    # declares() early-return stopped firing and it fell through to Claude's
    # settings-file logic, answering `refuted` about a file Codex never arms.
    # Unreachable in practice (run_probes dispatches by the row's probe id),
    # so this closes it latently -- the probe answers about the capability it
    # was MAPPED to measure, or not at all.
    state, by, detail = claude_probes.probe_read_guard_armed(
        "codex", session_root=str(tmp_path))
    assert state == hosts.UNKNOWN, (state, by, detail)
    assert ".claude" not in detail
    # Claude's row maps it, so nothing about the real subject moves.
    assert hosts.spec("claude").probes[hosts.READ_SCOPE_CONFINED] == claude_probes.READ_GUARD_ARMED
    assert claude_probes.probe_read_guard_armed(
        "claude", session_root=str(tmp_path))[0] != hosts.UNKNOWN
