import copy
import json
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
        "reads": [{"isError": False, "content": [{"type": "text", "text": "inside fixture"}]},
                  {"isError": True, "content": [{"type": "text", "text": "outside this entry scope"}]}],
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

    measured = codex_probes._codex_surfaces(str(registered), inspector=inspect)
    assert len(measured) == len(probes_common.DRIVER_ROLES) + 1
    assert len(set(seen)) == len(probes_common.DRIVER_ROLES) + 1


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
