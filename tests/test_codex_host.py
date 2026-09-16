"""Policy/transport fixtures only: never run a host binary or open a socket."""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib
from types import SimpleNamespace

import pytest

import scripts.codex_host as codex_host


MODEL = {"slug": "gpt-test", "base_instructions": "same model instructions",
         "apply_patch_tool_type": "freeform", "multi_agent_version": "v1",
         "tool_mode": "code_mode_only", "context_window": 123456}


@pytest.fixture(autouse=True)
def _only_test_owned_cwds(tmp_path, monkeypatch):
    # Even launch scratch directories stay under this test's temp fixture.
    original = codex_host.tempfile.mkdtemp

    def temporary(suffix=None, prefix=None, dir=None):
        # Spelled out rather than *args/**kwargs: TemporaryDirectory calls
        # mkdtemp POSITIONALLY, so a setdefault("dir", ...) collides with it.
        return original(suffix, prefix, tmp_path if dir is None else dir)

    monkeypatch.setattr(codex_host.tempfile, "mkdtemp", temporary)
    yield
    for path in tuple(codex_host._COMMAND_DIRS):
        if Path(path).is_relative_to(tmp_path.resolve()):
            codex_host.cleanup_command(["--cd", path])


def _fake_catalog(argv, **kwargs):
    assert argv == ["codex", "debug", "models", "--bundled"]
    assert kwargs["timeout"] == codex_host.PROBE_TIMEOUT
    return SimpleNamespace(returncode=0, stdout=json.dumps({"models": [MODEL]}), stderr="")


def _case(tmp_path):
    root = tmp_path.resolve() / "review"
    root.mkdir(exist_ok=True)
    entry = {"id": "setup-scan", "agent": None, "model": "gpt-test", "prompt": "not on argv"}
    env = {"PATH": "/inherited/bin", "UNRELATED_SECRET": "not forwarded to MCP",
           "PANOPTICON_ENTRY_ID": entry["id"],
           "PANOPTICON_WRITE_ALLOWLIST": str(root / "write.json"),
           "PANOPTICON_READ_SCOPE": str(root / "scope.json")}
    return root, entry, env


def _config(argv):
    return tomllib.loads("\n".join(argv[i + 1] for i, arg in enumerate(argv) if arg == "-c"))


def _register(root, name="panopticon-scout", mutation=None):
    config = codex_host.safety_config()
    config.update({"name": name, "description": "fixture", "developer_instructions": "Review only."})
    if mutation:
        mutation(config)
    args = list(codex_host._overrides(config))
    (root / (name + ".toml")).write_text("\n".join(args[1::2]), encoding="utf-8")


def test_safety_config_is_fresh_and_only_has_read_native_tools():
    first = codex_host.safety_config()
    assert first["sandbox_mode"] == "read-only"
    assert first["approval_policy"] == "never"
    assert first["web_search"] == "disabled"
    assert first["features"]["code_mode_host"] is True
    assert first["features"]["skip_host_skill_discovery"] is True
    assert not first["features"]["shell_tool"]
    assert not first["features"]["plugins"]
    assert not first["features"]["hooks"]
    server = first["mcp_servers"]["panopticon_scope"]
    assert server["enabled_tools"] == ["read_file", "search", "list_files"]
    assert server["args"][0] == "-I"
    assert server["required"] is True
    first["features"]["shell_tool"] = True
    assert not codex_host.safety_config()["features"]["shell_tool"]


def test_setup_command_is_isolated_and_catalog_only_removes_metadata_tools(tmp_path):
    root, entry, env = _case(tmp_path)
    argv = codex_host.command(entry, env, root, root / "run", runner=_fake_catalog)
    config = _config(argv)
    assert argv[:2] == ["codex", "exec"]
    assert argv[-1] == "-"
    assert entry["prompt"] not in argv
    for flag in ("--ignore-user-config", "--ignore-rules", "--ephemeral", "--strict-config"):
        assert flag in argv
    assert "--dangerously-bypass-approvals-and-sandbox" not in argv
    assert "--add-dir" not in argv
    assert argv[argv.index("--model") + 1] == entry["model"]
    cwd = Path(argv[argv.index("--cd") + 1])
    directory = Path(config["model_catalog_json"]).parent
    assert directory.parent == root / "run"
    assert not cwd.is_relative_to(root)
    assert directory.stat().st_mode & 0o077 == 0
    assert Path(config["log_dir"]).parent == directory
    assert Path(config["sqlite_home"]).parent == directory
    server_env = config["mcp_servers"]["panopticon_scope"]["env"]
    assert server_env == {**{key: env[key] for key in codex_host.ENV_KEYS},
                          "PANOPTICON_REVIEW_ROOT": str(root)}
    assert "UNRELATED_SECRET" not in server_env
    catalog = json.loads(Path(config["model_catalog_json"]).read_text())
    assert catalog["models"] == [{**MODEL, "apply_patch_tool_type": None, "multi_agent_version": None,
                                  "experimental_supported_tools": []}]
    again = codex_host.command(entry, env, root, root / "run", runner=_fake_catalog)
    assert _config(again)["model_catalog_json"] != config["model_catalog_json"]


def test_setup_without_named_model_preserves_native_default(tmp_path):
    root, entry, env = _case(tmp_path)
    entry["model"] = None
    argv = codex_host.command(entry, env, root, root / "run", runner=_fake_catalog)
    assert "--model" not in argv
    rows = json.loads(Path(_config(argv)["model_catalog_json"]).read_text())["models"]
    assert rows[0]["slug"] == MODEL["slug"]


def test_real_launch_validator_checks_finished_argv_and_exact_scope_binding(tmp_path):
    root, entry, env = _case(tmp_path)
    argv = codex_host.command(entry, env, root, root / "run", runner=_fake_catalog)
    assert codex_host.validate_command(argv, env, root) == _config(argv)
    config = _config(argv)
    config["features"]["shell_tool"] = True
    mutated = ["codex", "exec", *codex_host._overrides(config), "-"]
    with pytest.raises(ValueError, match="required control"):
        codex_host.validate_command(mutated, env, root)
    with pytest.raises(ValueError, match="scope-only"):
        codex_host.validate_command(argv, dict(env, PANOPTICON_ENTRY_ID="other"), root)
    config = _config(argv)
    config["model_provider"] = "unexpected"
    with pytest.raises(ValueError, match="unapproved"):
        codex_host.validate_command(["codex", *codex_host._overrides(config)], env, root)


def test_cleanup_refuses_unallocated_paths_and_releases_owned_cwd(tmp_path):
    root, entry, env = _case(tmp_path)
    codex_host.cleanup_command(["--cd", str(root)])
    assert root.is_dir()
    argv = codex_host.command(entry, env, root, root / "run", runner=_fake_catalog)
    cwd = Path(argv[argv.index("--cd") + 1])
    assert cwd.exists()
    codex_host.cleanup_command(argv)
    assert not cwd.exists()
    codex_host.cleanup_command(argv)  # idempotent; never delete a replacement


def test_target_local_scratch_root_is_rejected(tmp_path, monkeypatch):
    root, entry, env = _case(tmp_path)
    original = codex_host.tempfile.mkdtemp

    def target_local(suffix=None, prefix=None, dir=None):
        return original(suffix, prefix, root if dir is None else dir)

    monkeypatch.setattr(codex_host.tempfile, "mkdtemp", target_local)
    with pytest.raises(ValueError, match="outside the review root"):
        codex_host.command(entry, env, root, root / "run", runner=_fake_catalog)
    assert not list(root.glob("panopticon-codex-cwd-*"))


def test_registered_shell_policy_and_mutations_reach_effective_launch(tmp_path):
    root, entry, env = _case(tmp_path)
    entry["agent"] = "panopticon-scout"

    def mutate(config):
        config["features"]["shell_tool"] = True
        config["features"]["unified_exec"] = True
        config["model_provider"] = "untrusted provider is not forwarded"
        config["notify"] = ["untrusted command is not forwarded"]
        config["mcp_servers"]["panopticon_scope"]["command"] = "/untrusted/server"

    _register(root, mutation=mutate)
    argv = codex_host.command(entry, env, root, root / "run", runner=_fake_catalog, registration_dir=root)
    config = _config(argv)
    assert config["developer_instructions"] == "Review only."
    assert config["features"]["shell_tool"] is True  # probe must be able to refute this
    assert config["features"]["unified_exec"] is True
    assert "model_provider" not in config
    assert "notify" not in config
    assert config["mcp_servers"]["panopticon_scope"]["command"] != "/untrusted/server"


@pytest.mark.parametrize("agent", [
    "panopticon-scout", "panopticon-advisor", "panopticon-domain-panel", "panopticon-domain-advisor",
])
def test_emitted_role_placeholder_is_replaced_by_scoped_broker(tmp_path, agent):
    from scripts import dispatch

    root, entry, env = _case(tmp_path)
    registration_dir = tmp_path / "agents"
    dispatch.emit_host_agents("codex", registration_dir)
    entry["agent"] = agent
    entry["id"] = env["PANOPTICON_ENTRY_ID"] = "review-entry"
    registered = tomllib.loads((registration_dir / (agent + ".toml")).read_text())
    argv = codex_host.command(entry, env, root, root / "run", runner=_fake_catalog,
                              registration_dir=registration_dir)
    server = codex_host.validate_command(argv, env, root)["mcp_servers"]["panopticon_scope"]
    expected = codex_host.safety_config()["mcp_servers"]["panopticon_scope"]
    expected["enabled_tools"] = registered["mcp_servers"]["panopticon_scope"]["enabled_tools"]
    expected["env"] = {**{key: env[key] for key in codex_host.ENV_KEYS},
                       "PANOPTICON_REVIEW_ROOT": str(root)}
    assert server == expected


@pytest.mark.parametrize("role_file", [
    "scout.md", "advisor.md", "domain-panel.md", "domain-advisor.md",
])
def test_prompt_tool_policy_names_exactly_the_launched_tools(tmp_path, role_file):
    """P14 (run-13): the prose half of the contract, bound to the launch half.

    The reviewer is told what it may call by `dispatch._tool_policy_line`; what
    it CAN call is the `enabled_tools` allowlist this module puts on the argv,
    read back off that argv by `validate_command`. Run-13 proved the two had
    drifted -- the paragraph offered a shell the broker never exposed -- so the
    two lists are compared here rather than maintained in parallel by hand.

    Compared as SETS, matching what `validate_command` accepts off the argv
    (codex_host.py I-2: a role's allowlist is a non-empty subset in any order).
    The paragraph is role-blind today because every shipped template grants
    Read+Grep+Glob; if one ever narrows, the remedy is to map that role's
    `tool_policy.allowed` through the emitter's vocabulary table rather than to
    loosen this assertion -- #1677."""
    from scripts import dispatch

    root, entry, env = _case(tmp_path)
    registration_dir = tmp_path / "agents"
    dispatch.emit_host_agents("codex", registration_dir)
    entry["agent"] = dispatch.registered_agent_name(role_file)
    entry["id"] = env["PANOPTICON_ENTRY_ID"] = "review-entry"
    argv = codex_host.command(entry, env, root, root / "run", runner=_fake_catalog,
                              registration_dir=registration_dir)
    launched = codex_host.validate_command(argv, env, root)["mcp_servers"]["panopticon_scope"]
    meta, _body = dispatch.load_template(role_file)
    named = re.findall(r"`([a-z_]+)` \(", dispatch._tool_policy_line(meta, "codex"))
    assert set(named) == set(launched["enabled_tools"])


@pytest.mark.parametrize("agent", ["../panopticon-scout", "/panopticon-scout", "panopticon-scout.toml", "other"])
def test_rejects_shell_path_traversal(tmp_path, agent):
    root, entry, env = _case(tmp_path)
    entry["agent"] = agent
    with pytest.raises(ValueError, match="shell name"):
        codex_host.command(entry, env, root, root, runner=_fake_catalog, registration_dir=root)


def test_rejects_unregistered_nonsetup_and_mismatched_shell(tmp_path):
    root, entry, env = _case(tmp_path)
    entry["id"] = "review-entry"
    with pytest.raises(ValueError, match="registered shell"):
        codex_host.command(entry, env, root, root, runner=_fake_catalog, registration_dir=root)
    entry["agent"] = "panopticon-scout"
    (root / "panopticon-scout.toml").write_text('name="panopticon-advisor"')
    with pytest.raises(ValueError, match="name mismatch"):
        codex_host.command(entry, env, root, root, runner=_fake_catalog, registration_dir=root)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO fixture")
def test_registered_fifo_is_rejected_without_waiting_for_a_writer(tmp_path):
    root, entry, env = _case(tmp_path)
    entry["agent"] = "panopticon-scout"
    os.mkfifo(root / "panopticon-scout.toml")
    with pytest.raises(ValueError, match="regular file"):
        codex_host.command(entry, env, root, root, runner=_fake_catalog, registration_dir=root)


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="native no-follow open required")
def test_rejects_symlinked_shell_and_runtime_folder(tmp_path):
    root, entry, env = _case(tmp_path)
    (root / "outside").write_text("precious")
    (root / "panopticon-scout.toml").symlink_to(root / "outside")
    entry["agent"] = "panopticon-scout"
    with pytest.raises(OSError):
        codex_host.command(entry, env, root, root, runner=_fake_catalog, registration_dir=root)
    entry["agent"] = None
    (root / "linked").symlink_to(root, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinks"):
        codex_host.command(entry, env, root, root / "linked" / "run", runner=_fake_catalog)
    assert (root / "outside").read_text() == "precious"


@pytest.mark.parametrize("key", codex_host.ENV_KEYS)
def test_missing_binding_fails_before_catalog_launch(tmp_path, key):
    root, entry, env = _case(tmp_path)
    env.pop(key)

    def forbidden_launch(*args, **kwargs):
        pytest.fail("invalid entry must not launch anything")

    with pytest.raises(ValueError, match="binding"):
        codex_host.command(entry, env, root, root, runner=forbidden_launch)


@pytest.mark.parametrize("catalog", [{"models": []}, {"models": [MODEL, MODEL]}])
def test_absent_or_ambiguous_model_fails_closed(tmp_path, catalog):
    root, entry, env = _case(tmp_path)

    def fake(*args, **kwargs):
        return SimpleNamespace(returncode=0, stdout=json.dumps(catalog))

    with pytest.raises(ValueError, match="absent or ambiguous") as caught:
        codex_host.command(entry, env, root, root, runner=fake)
    # I-8: the pin is to one CLI build's bundled catalog, and the failure is
    # fatal for every entry of that role. Name the way out.
    assert "PANOPTICON_MODEL_" in str(caught.value)


def _requests(extra_tool=None):
    names = ["list_mcp_resources", "list_mcp_resource_templates", "read_mcp_resource",
             "mcp__panopticon_scope__read_file", "mcp__panopticon_scope__search", "mcp__panopticon_scope__list_files"]
    if extra_tool:
        names.append(extra_tool)
    surface = {"tools": names, "forbidden": dict.fromkeys(
        ("exec", "patch", "spawn", "fetch", "process", "require"), "undefined"),
        "reads": [{"isError": False}, {"isError": True}]}
    return [{"model": "gpt-test", "input": [{"type": "additional_tools", "tools": [{
        "type": "namespace", "name": "functions", "tools": [
            {"name": name} for name in ("exec", "wait", "request_user_input")]}]}]},
        {"input": [{"type": "custom_tool_call_output", "call_id": "tool_probe", "output": [
            {"type": "input_text", "text": "Script completed"},
            {"type": "input_text", "text": json.dumps({"panopticon_surface": surface})}]}]}]


def test_effective_surface_includes_deferred_and_direct_tools_and_preserves_mutation():
    result = codex_host._surface_result(_requests("exec_command"))
    assert result["model"] == "gpt-test"
    assert "exec_command" in result["tools"]  # do not filter a refuting observation
    assert result["direct_tools"] == ["functions.exec", "functions.wait", "functions.request_user_input"]
    assert result["reads"] == [{"isError": False}, {"isError": True}]


def test_top_level_responses_tools_cannot_hide_from_effective_probe():
    requests = _requests()
    requests[0]["tools"] = [{"type": "web_search"}]
    result = codex_host._surface_result(requests)
    assert "unproven Responses top-level tool surface" in result["direct_tools"]


@pytest.mark.parametrize("requests", [[], [{}], [{}, {}], [{}, {"input": []}]])
def test_missing_effective_observation_is_not_inferred_from_config(requests):
    with pytest.raises(ValueError, match="effective"):
        codex_host._surface_result(requests)


def test_probe_script_quotes_paths_as_data_and_rejects_an_incomplete_set():
    paths = ['inside"; text("not code")', "outside\\path\nline", "hard-link"]
    script = codex_host._probe_script(paths)
    assert json.dumps(paths) in script
    assert "ALL_TOOLS.map" in script
    assert "tools.mcp__panopticon_scope__read_file" in script
    # #1642: the third path is the planted hard link, and a measurement missing
    # it would leave the probe's refutation row unmeasured.
    for incomplete in (["only-one"], paths[:2]):
        with pytest.raises(ValueError, match="triple"):
            codex_host._probe_script(incomplete)


def test_inspection_uses_same_command_and_injected_transport_without_network(tmp_path, monkeypatch):
    root, entry, env = _case(tmp_path)
    captured = {}

    def fake_transport(argv, child_env, runner, script):
        captured.update(argv=argv, env=child_env, runner=runner, script=script)
        return copy.deepcopy(_requests())

    monkeypatch.setattr(codex_host, "_capture_requests", fake_transport)
    result = codex_host.inspect_surface(entry, env, root, root / "run", runner=_fake_catalog,
                                         probe_paths=("inside", "outside", "linked"))
    assert result["model"] == "gpt-test"
    assert captured["runner"] is _fake_catalog
    assert captured["env"] == env
    assert _config(captured["argv"])["features"]["shell_tool"] is False
    assert '["inside", "outside", "linked"]' in captured["script"]


def test_transport_is_local_only_and_closes_on_failure(monkeypatch):
    captured = {}

    class FakeServer:
        server_port = 12345

        def __init__(self, address, handler):
            assert address == ("127.0.0.1", 0)

        def serve_forever(self):
            pass

        def shutdown(self):
            captured["shutdown"] = True

        def server_close(self):
            captured["closed"] = True

    def fake(argv, **kwargs):
        config = _config(argv)
        provider = config["model_providers"]["panopticon_probe"]
        assert provider["base_url"] == "http://127.0.0.1:12345/v1"
        assert provider["requires_openai_auth"] is False
        assert provider["request_max_retries"] == 0
        assert provider["stream_max_retries"] == 0
        assert kwargs["timeout"] == codex_host.PROBE_TIMEOUT
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr(codex_host.http.server, "ThreadingHTTPServer", FakeServer)
    with pytest.raises(subprocess.TimeoutExpired):
        codex_host._capture_requests(["codex", "exec", "-"], {}, fake, "safe script")
    assert captured == {"shutdown": True, "closed": True}


def test_launch_diagnostic_is_bounded_and_redacts_credentials():
    proc = SimpleNamespace(returncode=2, stderr="Unknown configuration key\nAuthorization: Bearer private-secret\n"
                           "api_key = 'private-secret'\nsk-123456789secret\n" + "x" * 4000)
    detail = codex_host._launch_error(proc)
    assert "Unknown configuration key" in detail
    assert "exit 2" in detail
    assert "private-secret" not in detail
    assert "123456789secret" not in detail
    assert len(detail) < 2100


def test_the_unregistered_reviewer_error_names_the_emit_command(tmp_path):
    # I-1: "Codex reviewer requires a registered shell" named no remedy, and
    # the loop repeated it three times per entry.
    root, entry, env = _case(tmp_path)
    entry["id"] = "review-entry"
    with pytest.raises(ValueError) as caught:
        codex_host.command(entry, env, root, root, registration_dir=root)
    assert ("run: python3 skill/scripts/dispatch.py --emit-host-agents codex"
            in str(caught.value))


# --- I-2: the emitter narrows per role; the validator must accept that -------


def test_every_emitted_role_shell_builds_and_validates_a_real_launch(tmp_path):
    from scripts import dispatch
    registered = tmp_path / "registered"
    dispatch.emit_host_agents("codex", str(registered))
    root, _entry, env = _case(tmp_path)
    for role, role_file in sorted(dispatch.ROLE_FILES.items()):
        entry = {"id": "review-" + role, "model": "gpt-test",
                 "agent": dispatch.registered_agent_name(role_file)}
        bound = dict(env, PANOPTICON_ENTRY_ID=entry["id"])
        argv = codex_host.command(entry, bound, root, root / "run", runner=_fake_catalog,
                                  registration_dir=registered)
        try:
            assert codex_host.validate_command(argv, bound, root)
        finally:
            codex_host.cleanup_command(argv)


def test_a_role_registering_fewer_read_tools_still_launches(tmp_path):
    root, entry, env = _case(tmp_path)
    entry["agent"] = "panopticon-scout"
    _register(root, mutation=lambda config: config["mcp_servers"]["panopticon_scope"].update(
        enabled_tools=["search", "read_file"]))
    argv = codex_host.command(entry, env, root, root / "run", runner=_fake_catalog,
                              registration_dir=root)
    try:
        config = codex_host.validate_command(argv, env, root)
        assert config["mcp_servers"]["panopticon_scope"]["enabled_tools"] == ["search", "read_file"]
    finally:
        codex_host.cleanup_command(argv)


@pytest.mark.parametrize("enabled", [[], ["read_file", "shell"], "read_file"])
def test_an_empty_or_foreign_read_tool_allowlist_still_refuses(tmp_path, enabled):
    root, entry, env = _case(tmp_path)
    entry["agent"] = "panopticon-scout"
    _register(root, mutation=lambda config: config["mcp_servers"]["panopticon_scope"].update(
        enabled_tools=enabled))
    try:
        argv = codex_host.command(entry, env, root, root / "run", runner=_fake_catalog,
                                  registration_dir=root)
    except ValueError:
        return                          # refused before any launch is built
    try:
        with pytest.raises(ValueError, match="scope-only"):
            codex_host.validate_command(argv, env, root)
    finally:
        codex_host.cleanup_command(argv)


def test_cleanup_releases_the_per_entry_runtime_directory(tmp_path):
    # I-7: command() creates one codex-entry-* folder per launch, holding the
    # catalog copy, logs/ and sqlite/. cleanup_command removed only the --cd
    # scratch, so a real run left hundreds of them -- with Codex logs in them --
    # under .panopticon/runs/<tag>/.
    root, entry, env = _case(tmp_path)
    run = root / "run"
    argv = codex_host.command(entry, env, root, run, runner=_fake_catalog)
    directory = Path(_config(argv)["model_catalog_json"]).parent
    (directory / "logs").mkdir(parents=True, exist_ok=True)
    (directory / "logs" / "codex.log").write_text("reply text", encoding="utf-8")
    assert directory.is_dir()
    codex_host.cleanup_command(argv)
    assert not directory.exists()
    assert list(run.iterdir()) == []
    codex_host.cleanup_command(argv)            # idempotent


def test_cleanup_never_removes_a_directory_this_module_did_not_allocate(tmp_path):
    root, entry, env = _case(tmp_path)
    argv = codex_host.command(entry, env, root, root / "run", runner=_fake_catalog)
    directory = Path(_config(argv)["model_catalog_json"]).parent
    foreign = tmp_path / "not-ours"
    foreign.mkdir()
    (foreign / "keep").write_text("precious", encoding="utf-8")
    codex_host.cleanup_command(["--cd", str(foreign)])
    assert (foreign / "keep").read_text() == "precious"
    # An argv naming an allocated cwd but pointing the runtime dir elsewhere
    # cannot redirect the rmtree: the target comes from the registry, not argv.
    codex_host.cleanup_command([*argv[:-1], "-c", "log_dir=%s" % json.dumps(str(foreign)), "-"])
    assert (foreign / "keep").read_text() == "precious"
    assert not directory.exists()


@pytest.mark.parametrize("catalog", [{"models": []}, {"models": [MODEL, MODEL]}])
def test_a_refused_launch_leaves_no_runtime_directory_behind(tmp_path, catalog):
    # N-M4: the codex-entry-* folder is created BEFORE _catalog() runs and
    # before it is recorded in _COMMAND_DIRS, so I-8's own documented failure
    # -- a CLI build whose catalog spells the tier differently -- leaked one
    # directory per attempt, three per entry, on a run that was already
    # failing and that cleanup_command could never find.
    root, entry, env = _case(tmp_path)
    run = root / "run"

    def fake(*args, **kwargs):
        return SimpleNamespace(returncode=0, stdout=json.dumps(catalog), stderr="")

    with pytest.raises(ValueError, match="absent or ambiguous"):
        codex_host.command(entry, env, root, run, runner=fake)
    assert list(run.iterdir()) == []
    assert not any(str(path).startswith(str(run)) for path in codex_host._COMMAND_DIRS)


def test_an_output_schema_outside_the_published_reference_dir_is_refused(tmp_path):
    # D10 ruling 3: the argv allowlist gains exactly two tokens, and the value
    # half of that pair is a PATH. The entry it comes from travels through
    # `.panopticon/dispatch-request.json` inside the reviewed tree, so the
    # validator -- which exists to refuse a changed launch before any model
    # request -- has to hold it to the schemas panopticon publishes.
    import scripts._version as version
    root, entry, env = _case(tmp_path)
    published = os.path.abspath(version.reference_path("advisor-verdict-schema.json"))
    argv = codex_host.command(entry, env, root, root / "run", runner=_fake_catalog,
                              schema_argv=["--output-schema", published])
    assert argv[-3:] == ["--output-schema", published, "-"]
    assert codex_host.validate_command(argv, env, root)
    outsider = tmp_path / "mine.json"
    outsider.write_text("{}", encoding="utf-8")
    for path in (str(outsider), "/etc/passwd"):
        forged = [*argv[:-3], "--output-schema", path, "-"]
        with pytest.raises(ValueError, match="output schema"):
            codex_host.validate_command(forged, env, root)
    with pytest.raises(ValueError, match="output schema"):
        codex_host.validate_command([*argv[:-3], "--output-schema"], env, root)
