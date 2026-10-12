import copy
import dataclasses
import json
import os
import subprocess
from unittest import mock

import pytest

from scripts import codex_host, dispatch, host_probes, hosts
import scripts.probes.claude as claude_probes
import scripts.probes.codex as codex_probes
import scripts.probes.common as probes_common


HOST_GLOBALS = {
    "ALL_TOOLS", "as_settled", "audio", "clearTimeout", "exit", "generatedImage",
    "image", "load", "notify", "setTimeout", "store", "stream_settled", "text",
    "tools", "yield_control",
}
MODULE_IMPORTS = {
    "node:fs", "fs", "node:fs/promises", "node:child_process", "node:module",
    "node:worker_threads", "node:net", "node:http", "node:https", "node:dgram",
    "node:tls", "file:///tmp/panopticon-probe.mjs",
}


def surfaces():
    surface = {
        "tools": ["mcp__panopticon_scope__read_file", "mcp__panopticon_scope__search",
                  "mcp__panopticon_scope__list_files", "list_mcp_resources",
                  "list_mcp_resource_templates", "read_mcp_resource"],
        "direct_tools": ["functions.exec", "functions.wait", "functions.request_user_input"],
        "mcp_servers": ["panopticon_scope"],
        "globals": sorted(HOST_GLOBALS),
        "imports": {name: {"ok": False, "error": "unsupported import in exec"}
                    for name in MODULE_IMPORTS},
        "resources": {
            "list": {"ok": True, "value": '{"resources":[]}'},
            "templates": {"ok": True, "value": '{"resourceTemplates":[]}'},
            "read": {"ok": False, "error": "resources/read failed: method not found"},
        },
        "forbidden": dict.fromkeys(("exec", "patch", "spawn", "fetch", "process", "require"), "undefined"),
        # Third read (#1642): the hard link planted INSIDE the directory grant.
        # The wording is the broker's own, because that is what the probe reads.
        "reads": [{"isError": False, "content": [{"type": "text", "text": "inside fixture"}]},
                  {"isError": True, "content": [{"type": "text", "text": "outside this entry scope"}]},
                  {"isError": True, "content": [{"type": "text", "text": "Read tool refused: read scope "
                    "denies a hard-linked file inside a directory grant (st_nlink=2)"}]}],
    }
    paths = [dispatch.registered_agent_filename("codex", dispatch.ROLE_FILES[role])
             for role in probes_common.DRIVER_ROLES]
    paths.append("setup-scan (native default model and directory scope)")
    return [(path, copy.deepcopy(surface)) for path in paths]


@pytest.mark.parametrize("probe,probe_id", [
    (codex_probes.probe_codex_tool_policy, codex_probes.CODEX_EFFECTIVE_TOOLS),
    (codex_probes.probe_codex_read_scope, codex_probes.CODEX_READ_SCOPE),
    (codex_probes.probe_codex_write_surface, codex_probes.CODEX_WRITE_SURFACE_ABSENT),
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
def test_native_tool_policy_mutation_refutes_all_bearing_security_claims(change, tmp_path):
    measured = surfaces()
    change(measured[-1][1])
    for probe in (codex_probes.probe_codex_tool_policy,
                  codex_probes.probe_codex_read_scope,
                  codex_probes.probe_codex_write_surface):
        state, _by, detail = probe("codex", settings_path=str(tmp_path / "settings.json"),
                                  measure=lambda: measured)
        assert state == hosts.REFUTED
        assert measured[-1][0] in detail


def test_the_non_ecmascript_host_global_allowlist_is_exact():
    assert codex_probes.CODE_MODE_HOST_GLOBALS == HOST_GLOBALS


WRITE_ROUTE_MUTATIONS = {
    "mcp-write-tool": lambda s: s["tools"].append("mcp__panopticon_scope__write_file"),
    "direct-write-tool": lambda s: s["direct_tools"].append("functions.apply_patch"),
    "mcp-server": lambda s: s["mcp_servers"].append("reviewer_supplied"),
    "host-global": lambda s: s["globals"].append("writeFile"),
    "filesystem-import": lambda s: s["imports"].update(
        {"node:fs": {"ok": True, "value": ["writeFile"]}}),
    "resource": lambda s: s["resources"].update(
        {"list": {"ok": True, "value": '{"resources":[{"uri":"file:///tmp/x"}]}'}}),
    "resource-template": lambda s: s["resources"].update(
        {"templates": {"ok": True, "value":
                       '{"resourceTemplates":[{"uriTemplate":"file:///{path}"}]}'}}),
    "resource-read": lambda s: s["resources"].update(
        {"read": {"ok": True, "value": "reviewer-selected bytes"}}),
}


@pytest.mark.parametrize("role_index", range(len(probes_common.DRIVER_ROLES) + 1),
                         ids=(*probes_common.DRIVER_ROLES, "shell-less-setup"))
@pytest.mark.parametrize("route,change", WRITE_ROUTE_MUTATIONS.items(),
                         ids=WRITE_ROUTE_MUTATIONS)
def test_any_write_route_on_any_role_refutes_the_omission_proof(
        role_index, route, change, tmp_path):
    measured = surfaces()
    change(measured[role_index][1])
    state, by, detail = codex_probes.probe_codex_write_surface(
        "codex", settings_path=str(tmp_path / "settings.json"),
        measure=lambda: measured)
    assert state == hosts.REFUTED, route
    assert by == codex_probes.CODEX_WRITE_SURFACE_ABSENT
    assert measured[role_index][0] in detail


def test_missing_or_duplicate_role_measurements_do_not_prove_omission(tmp_path):
    complete = surfaces()
    cases = (complete[:-1], complete[:-1] + [copy.deepcopy(complete[0])])
    for measured in cases:
        state, by, detail = codex_probes.probe_codex_write_surface(
            "codex", settings_path=str(tmp_path / "settings.json"),
            measure=lambda: measured)
        assert (state, by) == (hosts.UNKNOWN, codex_probes.CODEX_WRITE_SURFACE_ABSENT)
        assert "every registered role" in detail


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


@pytest.mark.parametrize("probe", [codex_probes.probe_codex_tool_policy,
                                   codex_probes.probe_codex_read_scope,
                                   codex_probes.probe_codex_write_surface])
def test_unavailable_runtime_is_unknown_with_reason(probe, tmp_path):
    state, _by, detail = probe("codex", settings_path=str(tmp_path / "settings.json"),
                               measure=mock.Mock(side_effect=FileNotFoundError("codex not installed")))
    assert state == hosts.UNKNOWN
    assert "codex not installed" in detail
    assert probe("codex", settings_path=str(tmp_path / "settings.json"), measure=lambda: [])[0] == hosts.UNKNOWN


def test_a_surface_timeout_is_unknown_and_names_the_180_second_boundary(tmp_path):
    """#2923 B: exhausted confinement is distinct from the observed 64.8s success."""
    from scripts import codex_host

    timeout = subprocess.TimeoutExpired(["codex", "exec"], codex_host.PROBE_TIMEOUT)
    state, _by, detail = codex_probes.probe_codex_tool_policy(
        "codex", settings_path=str(tmp_path / "settings.json"),
        measure=mock.Mock(side_effect=timeout))
    assert state == hosts.UNKNOWN
    assert str(codex_host.PROBE_TIMEOUT) in detail
    assert "timed out" in detail.lower()


def test_missing_shell_is_refuted_without_invoking_runtime(tmp_path):
    with mock.patch("scripts.codex_host.inspect_surface", side_effect=AssertionError("no launch")) as inspector:
        state, _by, detail = codex_probes.probe_codex_tool_policy(
            "codex", registration_dir=str(tmp_path), settings_path=str(tmp_path / "settings.json"))
    assert state == hosts.REFUTED
    assert "reviewer shell is missing" in detail
    inspector.assert_not_called()


@pytest.mark.parametrize("probe,probe_id", [
    (codex_probes.probe_codex_tool_policy, codex_probes.CODEX_EFFECTIVE_TOOLS),
    (codex_probes.probe_codex_read_scope, codex_probes.CODEX_READ_SCOPE),
    (codex_probes.probe_codex_write_surface, codex_probes.CODEX_WRITE_SURFACE_ABSENT),
])
def test_a_relative_codex_home_is_reported_instead_of_measured(probe, probe_id, tmp_path, monkeypatch):
    # COD-1638371699: the codex row as `CODEX_HOME=.` leaves it, in a cwd that
    # ships the reviewed tree's own shells. The row's directory still points
    # at them (`./agents`, as before the fix), so a probe that measured it
    # instead of reporting the refusal would inspect the target's shells.
    planted = tmp_path / "agents"
    dispatch.emit_host_agents("codex", str(planted))
    monkeypatch.chdir(tmp_path)
    _home, refusal = hosts.codex_home(".")
    monkeypatch.setitem(hosts.HOSTS, "codex", dataclasses.replace(
        hosts.HOSTS["codex"], registration_dir=os.path.join(".", "agents"),
        registration_refusal=refusal))
    with mock.patch("scripts.codex_host.inspect_surface", side_effect=AssertionError("no launch")) as inspector:
        state, by, detail = probe("codex", settings_path=str(tmp_path / "settings.json"))
    assert (state, by) == (hosts.UNKNOWN, probe_id)
    assert refusal in detail
    inspector.assert_not_called()
    # An explicit directory is still measured.
    measured = codex_probes._codex_surfaces(str(planted), inspector=lambda *a, **k: surfaces()[0][1])
    assert len(measured) == len(probes_common.DRIVER_ROLES) + 1


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
        elif entry["id"] == codex_host.SETUP_PROBE_ID:
            assert entry["agent"] == "panopticon-setup-scan"
            assert entry["model"] is None
        else:
            assert entry["scope"]["files"] == [inside]
            assert root == run_dir
        assert outside not in entry["scope"]["files"]
        assert linked not in entry["scope"]["files"]
        assert env["PANOPTICON_ENTRY_ID"] == entry["id"]
        assert kwargs["registration_dir"] == str(registered)
        assert kwargs["probe_module"].startswith("file:")
        seen.append(entry["agent"])
        return surfaces()[0][1]

    measured = codex_probes._codex_surfaces(str(registered), inspector=inspect)
    assert len(measured) == len(probes_common.DRIVER_ROLES) + 1
    assert len(set(seen)) == len(probes_common.DRIVER_ROLES) + 1


def test_no_override_surface_measurement_builds_every_role_launch(tmp_path):
    """#2923 A: the model-neutral registered setup probe reaches measurement."""
    from scripts import codex_host

    registered = tmp_path / "registered"
    dispatch.emit_host_agents("codex", str(registered))
    catalog = [{"slug": "gpt-6-luna"}, {"slug": "gpt-6-sol"}]

    def inspect(entry, env, root, run_dir, **kwargs):
        argv = codex_host.command(
            entry, env, root, run_dir, registration_dir=kwargs["registration_dir"],
            catalog=lambda: catalog)
        try:
            codex_host.validate_command(argv, env, root)
        finally:
            codex_host.cleanup_command(argv)
        return copy.deepcopy(surfaces()[0][1])

    measured = codex_probes._codex_surfaces(str(registered), inspector=inspect)
    assert len(measured) == len(probes_common.DRIVER_ROLES) + 1
    for probe in (codex_probes.probe_codex_tool_policy,
                  codex_probes.probe_codex_read_scope,
                  codex_probes.probe_codex_write_surface):
        state, _by, _detail = probe(
            "codex", settings_path=str(tmp_path / "settings.json"),
            measure=lambda: measured)
        assert state == hosts.PROVEN


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
    assert artifact["capabilities"][hosts.ARTIFACT_WRITE_GUARD]["state"] == hosts.PROVEN
    read_row = artifact["capabilities"][hosts.READ_SCOPE_CONFINED]
    assert read_row["state"] == hosts.UNKNOWN
    assert "cross-device link" in read_row["detail"]
    # Fix round 2 (N3): the plant is attempted ONCE and fails machine-wide, so
    # the detail is not one arbitrary role's problem. It used to arrive as
    # "<whichever shell the loop reached first>.toml: ...", which an operator
    # reads as "the advisor role is broken".
    assert read_row["detail"].startswith("the hard-link refutation fixture could not be planted")
    assert ".toml" not in read_row["detail"]
    # Measured ONCE for all three probes, and with no probe paths at all: a
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
            for capability in (hosts.TOOL_POLICY_ENFORCED, hosts.READ_SCOPE_CONFINED,
                               hosts.ARTIFACT_WRITE_GUARD):
                assert artifact["capabilities"][capability]["state"] == hosts.PROVEN
        assert measure.call_count == 2


def test_the_probe_never_swallows_the_suites_launch_guard(tmp_path):
    # I-5: _codex_measure maps any exception to UNKNOWN, so a test that reached
    # a live `codex` and failed would still read as a clean "unavailable".
    from scripts import codex_host

    for probe in (codex_probes.probe_codex_tool_policy,
                  codex_probes.probe_codex_read_scope,
                  codex_probes.probe_codex_write_surface):
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
