import copy
import json
from unittest import mock

import pytest

from scripts import dispatch, host_probes, hosts


def surfaces():
    surface = {
        "tools": ["mcp__panopticon_scope__read_file", "mcp__panopticon_scope__search",
                  "mcp__panopticon_scope__list_files", "list_mcp_resources",
                  "list_mcp_resource_templates", "read_mcp_resource"],
        "direct_tools": ["functions.exec", "functions.wait", "functions.request_user_input"],
        "forbidden": dict.fromkeys(("exec", "patch", "spawn", "fetch", "process", "require"), "undefined"),
        "reads": [{"isError": False, "content": [{"type": "text", "text": "inside fixture"}]},
                  {"isError": True, "content": [{"type": "text", "text": "outside this entry scope"}]}],
    }
    return [(role + ".toml", copy.deepcopy(surface)) for role in (*host_probes.DRIVER_ROLES, "setup-scan")]


@pytest.mark.parametrize("probe,probe_id", [
    (host_probes.probe_codex_tool_policy, host_probes.CODEX_EFFECTIVE_TOOLS),
    (host_probes.probe_codex_read_scope, host_probes.CODEX_READ_SCOPE),
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
    for probe in (host_probes.probe_codex_tool_policy, host_probes.probe_codex_read_scope):
        state, _by, detail = probe("codex", settings_path=str(tmp_path / "settings.json"),
                                  measure=lambda: measured)
        assert state == hosts.REFUTED
        assert measured[-1][0] in detail


def test_widened_scope_mutation_refutes_actual_read_boundary(tmp_path):
    measured = surfaces()
    measured[0][1]["reads"][1] = {"isError": False, "content": [{"type": "text", "text": "outside read allowed"}]}
    state, by, detail = host_probes.probe_codex_read_scope(
        "codex", settings_path=str(tmp_path / "settings.json"), measure=lambda: measured)
    assert state == hosts.REFUTED
    assert by == host_probes.CODEX_READ_SCOPE
    assert "deny failed" in detail


@pytest.mark.parametrize("probe", [host_probes.probe_codex_tool_policy, host_probes.probe_codex_read_scope])
def test_unavailable_runtime_is_unknown_with_reason(probe, tmp_path):
    state, _by, detail = probe("codex", settings_path=str(tmp_path / "settings.json"),
                               measure=mock.Mock(side_effect=FileNotFoundError("codex not installed")))
    assert state == hosts.UNKNOWN
    assert "codex not installed" in detail
    assert probe("codex", settings_path=str(tmp_path / "settings.json"), measure=lambda: [])[0] == hosts.UNKNOWN


def test_missing_shell_is_refuted_without_invoking_runtime(tmp_path):
    with mock.patch("scripts.codex_host.inspect_surface", side_effect=AssertionError("no launch")) as inspector:
        state, _by, detail = host_probes.probe_codex_tool_policy(
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
        inside, outside = kwargs["probe_paths"]
        if entry["id"] == "setup-scan":
            assert entry["scope"] == {"files": [], "dirs": [root], "reads": []}
            assert entry["model"] is None
        else:
            assert entry["scope"]["files"] == [inside]
            assert root == run_dir
        assert outside not in entry["scope"]["files"]
        assert env["PANOPTICON_ENTRY_ID"] == entry["id"]
        assert kwargs["registration_dir"] == str(registered)
        seen.append(entry["agent"])
        return surfaces()[0][1]

    measured = host_probes._codex_surfaces(str(registered), inspector=inspect)
    assert len(measured) == len(host_probes.DRIVER_ROLES) + 1
    assert len(set(seen)) == len(host_probes.DRIVER_ROLES) + 1


def test_registry_dispatch_shares_measurement_only_within_one_invocation(tmp_path):
    with mock.patch.object(host_probes, "_codex_surfaces", side_effect=lambda _registration: surfaces()) as measure:
        for _ in range(2):
            artifact = host_probes.run_probes("codex", str(tmp_path), registration_dir=str(tmp_path),
                                              settings_path=str(tmp_path / "settings.json"))
            for capability in (hosts.TOOL_POLICY_ENFORCED, hosts.READ_SCOPE_CONFINED):
                assert artifact["capabilities"][capability]["state"] == hosts.PROVEN
        assert measure.call_count == 2
