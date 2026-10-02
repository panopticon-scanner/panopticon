"""Run-artifact reads are bounded before parsing and retain caller policies."""
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

import scripts.safe_write as safe_write
from scripts.synth import artifacts, cost, coverage_io, delta, integrity, plan, tool_axis


def _load_manifest(root):
    return tool_axis.ToolAxis.load(SimpleNamespace(run_id=None, files=[]),
                                  str(root), [], {}, set())


CASES = [
    ("groups.json", lambda root: plan.load_groups_json(str(root / "groups.json")), {}),
    ("dispatch-plan-driver.json", lambda root: plan.load_dispatch_plans(str(root)), []),
    ("panel-tools-context.json", lambda root: plan.load_panel_tools_context(str(root)),
     {"with": 0, "without": 0}),
    ("panel-test-inventory.json", lambda root: plan.load_test_inventory(str(root)), {}),
    ("scout-a.json", lambda root: plan.load_scout_requests(str(root)), (set(), 0)),
    ("usage.json", lambda root: cost.load_run_usage(str(root)), None),
    ("unenforced-ack.json", lambda root: integrity.read_unenforced_ack(
        str(root / "unenforced-ack.json")), {}),
    ("dispatch-plan-driver.json", lambda root: integrity._owes_a_snapshot(str(root)), False),
    ("coverage-a.json", lambda root: coverage_io.load_coverage_files(str(root)), []),
]


@pytest.mark.parametrize("filename,load,expected", CASES)
def test_deep_json_preserves_fallback_and_announces_rejection(tmp_path, capsys,
                                                            filename, load, expected):
    (tmp_path / filename).write_text("[" * 200000 + "]" * 200000)
    assert load(tmp_path) == expected
    assert filename in capsys.readouterr().err


@pytest.mark.parametrize("kind", ["manifest", "plan", "queue", "delta"])
def test_deep_json_retains_invalid_artifact_fact(tmp_path, kind):
    names = {"manifest": "tools-manifest.json", "plan": "dispatch-plan-driver.json",
             "queue": "verify-queue.json", "delta": "diff-hunks.json"}
    (tmp_path / names[kind]).write_text("[" * 200000 + "]" * 200000)
    if kind == "manifest":
        result = _load_manifest(tmp_path)
        assert result.manifest is None
        assert "RecursionError" in result.manifest_invalid
    elif kind == "plan":
        valid, seen, invalid = plan.load_dispatch_plans_detailed(str(tmp_path))
        assert valid == [] and seen == 1
        assert len(invalid) == 1 and "RecursionError" in invalid[0]["reason"]
    elif kind == "queue":
        queue, reason = integrity.load_verify_queue(str(tmp_path))
        assert queue is None and "RecursionError" in reason
    else:
        data, report = delta.load_diff_hunks_report(str(tmp_path / names[kind]))
        assert data == {} and report.payload_malformed == delta.MALFORMED_UNREADABLE


def test_manifest_oversize_is_invalid_before_repair(tmp_path):
    path = tmp_path / "tools-manifest.json"
    with path.open("w") as stream:
        stream.write('{"schema_version":1,"selected":[]}')
        stream.write(" " * (16 * 1024 * 1024))
    axis = _load_manifest(tmp_path)
    assert axis.manifest is None
    assert "read limit" in axis.manifest_invalid


def test_missing_optional_artifacts_keep_their_quiet_fallbacks(tmp_path, capsys):
    for _filename, load, expected in CASES:
        assert load(tmp_path) == expected
    axis = _load_manifest(tmp_path)
    assert axis.manifest is None and axis.manifest_invalid is None
    assert integrity.load_verify_queue(str(tmp_path)) == (None, None)
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("symlink", [False, True])
def test_fifo_artifact_returns_with_disclosure_without_waiting_for_writer(tmp_path, symlink):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    artifact = tmp_path / "coverage-a.json"
    if symlink:
        artifact.symlink_to(fifo)
    else:
        fifo.rename(artifact)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "skill")
    result = subprocess.run(
        [sys.executable, "-c",
         "import sys; from scripts.synth import coverage_io; "
         "assert coverage_io.load_coverage_files(sys.argv[1]) == []", str(tmp_path)],
        env=env, text=True, capture_output=True, timeout=5, check=False)
    assert result.returncode == 0, result.stderr
    assert "coverage-a.json" in result.stderr


def test_bounded_read_still_accepts_clean_manifest(tmp_path):
    data = {"schema_version": 1, "selected": [], "run_id": "current"}
    (tmp_path / "tools-manifest.json").write_text(json.dumps(data))
    axis = _load_manifest(tmp_path)
    assert axis.manifest == data and axis.manifest_invalid is None


@pytest.mark.parametrize("raw,expected", [(b"null", None), (b"[]", []),
                                         (b"false", False), ('"é"'.encode(), "é")])
def test_exact_byte_limit_is_inclusive_and_not_a_character_limit(tmp_path, raw, expected):
    path = tmp_path / "input.json"
    path.write_bytes(raw)
    assert artifacts.read_json(path, limit=len(raw)) == expected
    with pytest.raises(safe_write.ReadLimitExceeded, match="read limit"):
        artifacts.read_json(path, limit=len(raw)-1)


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_invalid_limit_uses_the_shared_reader_contract(tmp_path, limit):
    path = tmp_path / "input.json"
    path.write_text("{}")
    with pytest.raises(ValueError, match="^read limit must be a positive integer$"):
        artifacts.read_json(path, limit=limit)


def test_oversize_input_never_reaches_decoder(tmp_path, monkeypatch):
    path = tmp_path / "large.json"
    path.write_bytes(b'{}' + b' ' * 64)
    def unexpected_decode(*_args):
        pytest.fail("oversize bytes reached JSON decoder")
    monkeypatch.setattr(artifacts.json, "loads", unexpected_decode)
    with pytest.raises(safe_write.ReadLimitExceeded, match="read limit"):
        artifacts.read_json(path, limit=64)


def test_tolerant_envelope_parsing_is_opt_in(tmp_path):
    path = tmp_path / "agent.json"
    path.write_text('```json\n{"findings":[]}\n```')
    with pytest.raises(ValueError):
        artifacts.read_json(path)
    assert artifacts.read_json(path, tolerant=True) == {"findings": []}


@pytest.mark.parametrize("exception", [MemoryError(), RecursionError("too deep")])
def test_resource_errors_keep_a_named_reason(tmp_path, monkeypatch, exception):
    path = tmp_path / "input.json"
    path.write_text("{}")
    def fail_parse(_text):
        raise exception
    monkeypatch.setattr(artifacts.json, "loads", fail_parse)
    with pytest.raises(ValueError, match=type(exception).__name__):
        artifacts.read_json(path)


@pytest.mark.parametrize("raw", [b'{', b'"\xff"'])
def test_malformed_json_or_utf8_remains_a_parse_failure(tmp_path, raw):
    path = tmp_path / "input.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        artifacts.read_json(path)


def test_leaf_symlink_is_refused_but_parent_alias_is_supported(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    path = real / "input.json"
    path.write_text('{"ok":true}')
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    assert artifacts.read_json(alias / "input.json") == {"ok": True}
    leaf = tmp_path / "link.json"
    leaf.symlink_to(path)
    with pytest.raises(OSError):
        artifacts.read_json(leaf)
    assert path.read_text() == '{"ok":true}'


@pytest.mark.parametrize("kind", ["directory", "fifo", "symlink"])
def test_nonregular_verify_queue_is_invalid_not_absent(tmp_path, kind):
    path = tmp_path / "verify-queue.json"
    if kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        os.mkfifo(path)
    else:
        path.symlink_to(tmp_path / "absent")
    queue, reason = integrity.load_verify_queue(str(tmp_path))
    assert queue is None and reason and "cannot read verify queue" in reason


@pytest.mark.parametrize("failure_point", ["fstat", "fdopen"])
def test_descriptor_closes_when_inspection_or_wrapping_fails(tmp_path, monkeypatch, failure_point):
    path = tmp_path / "input.json"
    path.write_text("{}")
    opened = []
    real_open, real_fstat = os.open, os.fstat
    def track_open(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd
    def fail(*_args, **_kwargs):
        raise OSError("injected I/O failure")
    monkeypatch.setattr(artifacts.os, "open", track_open)
    monkeypatch.setattr(artifacts.os, failure_point, fail)
    with pytest.raises(OSError, match="injected"):
        artifacts.read_json(path)
    assert len(opened) == 1
    with pytest.raises(OSError):
        real_fstat(opened[0])


def test_device_is_refused_without_reading_bytes():
    with pytest.raises(safe_write.NonRegularFileError, match="regular file"):
        artifacts.read_json(os.devnull)
