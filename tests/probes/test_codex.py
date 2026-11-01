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
        "reads": [{"isError": False, "content": [{"type": "text", "text": "inside fixture"}]},
                  {"isError": True, "content": [{"type": "text", "text": "outside this entry scope"}]}],
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


def test_a_one_read_measurement_is_unknown_not_proven(tmp_path):
    measured = surfaces()
    for _path, surface in measured:
        surface["reads"] = surface["reads"][:1]
    state, _by, detail = codex_probes.probe_codex_read_scope(
        "codex", settings_path=str(tmp_path / "settings.json"), measure=lambda: measured)
    assert state == hosts.UNKNOWN
    assert "two-read" in detail
    measured = surfaces()
    for _path, surface in measured:
        surface["reads"] = surface["reads"] + [surface["reads"][0]]
    state, _by, detail = codex_probes.probe_codex_read_scope(
        "codex", settings_path=str(tmp_path / "settings.json"), measure=lambda: measured)
    assert (state, "two-read" in detail) == (hosts.UNKNOWN, True)


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
        inside, outside = kwargs["probe_paths"]
        assert os.stat(inside).st_nlink == 1 and os.stat(outside).st_nlink == 1
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


def test_a_role_granted_fewer_read_tools_passes_launch_and_probe_alike(tmp_path):
    """ARC-2742938782: launch validation and the posture probe agree on a
    narrowed role. `validate_command` takes a role's own allowlist (I-2), so
    the probe expects that role's grant -- not the whole broker -- and both
    still refuse a tool outside the broker surface."""
    from tests.test_codex_host import _case, _fake_catalog

    real = dispatch.load_template
    scout_file = dispatch.ROLE_FILES["scout"]

    def without_glob(role_file):
        meta, body = real(role_file)
        if role_file == scout_file:
            meta = copy.deepcopy(meta)
            meta["tool_policy"]["allowed"] = [
                tool for tool in meta["tool_policy"]["allowed"] if tool != "Glob"]
        return meta, body

    shell_name = dispatch.registered_agent_filename("codex", scout_file)
    settings = str(tmp_path / "settings.json")
    probes = (codex_probes.probe_codex_tool_policy, codex_probes.probe_codex_read_scope,
              codex_probes.probe_codex_write_surface)
    with mock.patch.object(dispatch, "load_template", without_glob):
        registered = tmp_path / "registered"
        dispatch.emit_host_agents("codex", str(registered))
        root, _entry, env = _case(tmp_path)
        entry = {"id": "probe-scout", "model": "gpt-test", "agent": "panopticon-scout"}
        bound = dict(env, PANOPTICON_ENTRY_ID=entry["id"])
        argv = codex_host.command(entry, bound, root, root / "run", runner=_fake_catalog,
                                  registration_dir=registered)
        try:
            launched = codex_host.validate_command(argv, bound, root)[
                "mcp_servers"]["panopticon_scope"]["enabled_tools"]
        finally:
            codex_host.cleanup_command(argv)
        assert sorted(launched) == ["read_file", "search"]

        def measured(tools):
            # Full shell paths, as `_codex_surfaces` returns them.
            rows = [(path if path.startswith("setup-scan") else str(registered / path), surface)
                    for path, surface in surfaces()]
            for path, surface in rows:
                if os.path.basename(path) == shell_name:
                    surface["tools"] = sorted(
                        {"list_mcp_resources", "list_mcp_resource_templates",
                         "read_mcp_resource"} | {"mcp__panopticon_scope__" + t for t in tools})
            return rows

        # The narrowed grant, measured as launched: proven by every claim.
        for probe in probes:
            assert probe("codex", settings_path=settings,
                         measure=lambda: measured(launched))[0] == hosts.PROVEN, probe
        # Wider than the grant, or a tool outside the broker: refuted.
        for tools in (["read_file", "search", "list_files"], [*launched, "write_file"]):
            for probe in probes:
                state, _by, detail = probe("codex", settings_path=settings,
                                           measure=lambda: measured(tools))
                assert state == hosts.REFUTED and shell_name in detail, (probe, tools)

    # ...and launch validation refuses that outside tool too.
    shell = registered / shell_name
    text = shell.read_text(encoding="utf-8")
    assert text.count('enabled_tools = ["read_file", "search"]') == 1
    shell.write_text(text.replace('enabled_tools = ["read_file", "search"]',
                                  'enabled_tools = ["read_file", "write_file"]'), encoding="utf-8")
    try:
        argv = codex_host.command(entry, bound, root, root / "run", runner=_fake_catalog,
                                  registration_dir=registered)
    except ValueError:
        return                          # refused before any launch is built
    try:
        with pytest.raises(ValueError, match="scope-only"):
            codex_host.validate_command(argv, bound, root)
    finally:
        codex_host.cleanup_command(argv)
