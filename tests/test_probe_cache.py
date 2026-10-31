"""#3272: host measurements are cached only in operator-owned state."""
import json
import os
import shutil

from scripts import hosts, probe_cache


CLAUDE = {"name": "claude", "path": "/operator/bin/claude",
          "version": "2.1.40 (Claude Code)", "sha256": "a" * 64, "size": 17}
RESULT = [hosts.PROVEN, "fixture-probe", "measured"]


def _cache(state, target, registration, app=None, host="claude"):
    os.environ["PANOPTICON_STATE_DIR"] = str(state)
    return probe_cache.ProbeCache(
        host, [app or CLAUDE], registration_dir=str(registration),
        session_root=str(target), settings_path=str(target / "host-settings.json"))


def test_cache_lives_operator_side_and_round_trips(tmp_path, monkeypatch):
    state, target, registration = (tmp_path / name for name in ("state", "target", "agents"))
    target.mkdir()
    registration.mkdir()
    monkeypatch.setenv("PANOPTICON_STATE_DIR", str(state))
    first = _cache(state, target, registration)
    first.put("probe", RESULT)
    first.flush()

    files = list(state.iterdir())
    assert [path.name for path in files] == ["host-probe-cache-claude.json"]
    assert not list(target.glob("*probe-cache*"))
    assert files[0].stat().st_mode & 0o077 == 0
    hit, value = _cache(state, target, registration).get("probe")
    assert hit and value == RESULT


def test_cli_sha_version_host_and_settings_are_cache_keys(tmp_path, monkeypatch):
    state, target, registration = (tmp_path / name for name in ("state", "target", "agents"))
    target.mkdir()
    registration.mkdir()
    settings = target / "host-settings.json"
    settings.write_text('{"hooks": []}', encoding="utf-8")
    monkeypatch.setenv("PANOPTICON_STATE_DIR", str(state))
    first = _cache(state, target, registration)
    first.put("probe", RESULT)
    first.flush()

    # A content-identical atomic rewrite is not a settings change.
    settings.write_text('{"hooks": []}', encoding="utf-8")
    assert _cache(state, target, registration).get("probe")[0]
    # The run folder also gains unrelated artifacts between driver calls.
    # Directory churn is not a probe setting and must not rebuy the probes.
    (target / "unrelated-artifact.json").write_text("{}", encoding="utf-8")
    assert _cache(state, target, registration).get("probe")[0]

    for app in (dict(CLAUDE, sha256="b" * 64),
                dict(CLAUDE, version="2.1.41 (Claude Code)")):
        assert not _cache(state, target, registration, app=app).get("probe")[0]

    settings.write_text('{"hooks": ["changed"]}', encoding="utf-8")
    assert not _cache(state, target, registration).get("probe")[0]

    kimi = {"name": "kimi", "path": "/operator/bin/kimi", "version": "1.4.0",
            "sha256": "a" * 64, "size": 17}
    assert not _cache(state, target, registration, app=kimi, host="kimi").get("probe")[0]


def test_missing_identity_and_malformed_cache_are_misses(tmp_path, monkeypatch):
    state, target, registration = (tmp_path / name for name in ("state", "target", "agents"))
    target.mkdir()
    registration.mkdir()
    monkeypatch.setenv("PANOPTICON_STATE_DIR", str(state))
    disabled = probe_cache.ProbeCache(
        "claude", [], registration_dir=str(registration), session_root=str(target))
    disabled.put("probe", RESULT)
    disabled.flush()
    assert not state.exists()

    state.mkdir()
    path = state / "host-probe-cache-claude.json"
    path.write_text(json.dumps({"schema_version": 999, "entries": {"probe": RESULT}}),
                    encoding="utf-8")
    assert not _cache(state, target, registration).get("probe")[0]


def test_an_unsafe_cache_file_is_a_miss(tmp_path, monkeypatch):
    state, target, registration = (tmp_path / name for name in ("state", "target", "agents"))
    target.mkdir()
    registration.mkdir()
    monkeypatch.setenv("PANOPTICON_STATE_DIR", str(state))
    first = _cache(state, target, registration)
    first.put("probe", RESULT)
    first.flush()

    path = state / "host-probe-cache-claude.json"
    path.chmod(0o644)
    assert not _cache(state, target, registration).get("probe")[0]


def test_kimi_operator_config_is_a_settings_input(tmp_path, monkeypatch):
    state, target, registration = (tmp_path / name for name in ("state", "target", "agents"))
    target.mkdir()
    registration.mkdir()
    kimi_home = tmp_path / "kimi-home"
    kimi_home.mkdir()
    config = kimi_home / "config.toml"
    config.write_text('[models.k2]\nprovider = "fixture"\n', encoding="utf-8")
    monkeypatch.setenv("PANOPTICON_STATE_DIR", str(state))
    monkeypatch.setenv("KIMI_CODE_HOME", str(kimi_home))
    app = {"name": "kimi", "path": "/operator/bin/kimi", "version": "1.4.0",
           "sha256": "a" * 64, "size": 17}
    first = _cache(state, target, registration, app=app, host="kimi")
    first.put("probe", RESULT)
    first.flush()
    assert _cache(state, target, registration, app=app, host="kimi").get("probe")[0]

    config.write_text('[models.k2]\nprovider = "changed"\n', encoding="utf-8")
    assert not _cache(state, target, registration, app=app, host="kimi").get("probe")[0]


def test_measurement_source_change_is_a_cache_miss(tmp_path, monkeypatch):
    state, target, registration = (tmp_path / name for name in ("state", "target", "agents"))
    target.mkdir()
    registration.mkdir()
    source_root = tmp_path / "copied-skill" / "scripts"
    shutil.copytree(probe_cache.SOURCE_ROOT, source_root,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    source = source_root / "write_guard_hook.py"
    monkeypatch.setattr(probe_cache, "SOURCE_ROOT", str(source_root), raising=False)
    monkeypatch.setenv("PANOPTICON_STATE_DIR", str(state))
    first = _cache(state, target, registration)
    first.put("probe", RESULT)
    first.flush()
    assert _cache(state, target, registration).get("probe")[0]

    # Same path, size and settings; one byte of measuring code moved.
    raw = source.read_bytes()
    source.write_bytes((b" " if raw[:1] != b" " else b"#") + raw[1:])
    assert not _cache(state, target, registration).get("probe")[0]


def test_measurement_source_digest_covers_guards_and_every_probe_module():
    names = set(probe_cache._measurement_source_names())
    required = {
        "guard_rules.py", "host_probes.py", "hosts.py", "probe_cache.py",
        "read_guard_hook.py", "write_guard_hook.py",
        os.path.join("probes", "claude_write_canary.py"),
    }
    probe_dir = os.path.join(probe_cache.SOURCE_ROOT, "probes")
    every_probe = {os.path.join("probes", name) for name in os.listdir(probe_dir)
                   if name.endswith(".py")}
    assert required | every_probe <= names


def test_cache_rows_expire_after_24_hours_and_reject_the_future(tmp_path, monkeypatch):
    state, target, registration = (tmp_path / name for name in ("state", "target", "agents"))
    target.mkdir()
    registration.mkdir()
    monkeypatch.setenv("PANOPTICON_STATE_DIR", str(state))
    monkeypatch.setattr(probe_cache, "_now", lambda: 1_000.0, raising=False)
    first = _cache(state, target, registration)
    first.put("probe", RESULT)
    first.flush()
    document = json.loads((state / "host-probe-cache-claude.json").read_text(
        encoding="utf-8"))
    assert document["entries"]["probe"]["measured_at"] == 1_000.0

    monkeypatch.setattr(probe_cache, "_now", lambda: 1_000.0 + 24 * 60 * 60)
    assert _cache(state, target, registration).get("probe")[0]
    monkeypatch.setattr(probe_cache, "_now", lambda: 1_000.0 + 24 * 60 * 60 + 1)
    assert not _cache(state, target, registration).get("probe")[0]
    monkeypatch.setattr(probe_cache, "_now", lambda: 999.0)
    assert not _cache(state, target, registration).get("probe")[0]
