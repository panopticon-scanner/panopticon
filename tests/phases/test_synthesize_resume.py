"""#2930: a failed synthesis attempt cannot become complete on plain resume."""
from copy import deepcopy
from functools import partial
import json
import os
from pathlib import Path
import subprocess
from unittest import mock

import pytest

import scripts.driver as driver
import scripts.run_manifest as run_manifest
import scripts.safe_write as safe_write
import scripts.synthesize as synthesize_cli
from scripts.phases import child, engine, runio, synthesize, validate
from scripts.synth import validate_schema
from tests.tools.git_repo import make_git_repo


def _write(path, document):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")


def _pending(root):
    return Path(runio._pano(root, "synthesize-pending.json"))


def _report(root):
    return Path(runio._report_out(root))


def _manifest(root):
    manifest = run_manifest.build_manifest(
        target=root, review_root=root, host="codex", security_mode="standard",
        flags={"tools": False}, scope={"mode": "repo", "target": None})
    run_manifest.write_manifest(root, manifest)
    _write(runio._pano(root, "groups.json"), {"mode": "repo", "groups": []})
    return manifest


@pytest.fixture
def review(tmp_path, monkeypatch):
    root = make_git_repo(tmp_path=tmp_path / "target")
    monkeypatch.chdir(root)
    manifest = _manifest(root)
    seed = tmp_path / "seed.json"
    assert synthesize_cli.main([
        "--repo", "--root", root, "--out", str(seed)]) == 0
    valid_report = json.loads(seed.read_text(encoding="utf-8"))
    assert validate_schema.schema_errors(valid_report) == []
    # This is the phase/resume protocol, with no host launches or Docker.
    monkeypatch.setattr(driver, "_establish_host_posture", lambda *args: None)
    return root, manifest, valid_report


def _resume(root):
    phases = [
        engine.Phase("synthesize", "deterministic",
                     synthesize.synthesize_done, synthesize.synthesize_execute),
        engine.Phase("validate", "deterministic",
                     validate.validate_done, validate.validate_execute),
    ]
    args = driver.parse_cli(["run", root, "--host", "codex", "--no-tools"])
    return driver.run(args, phases=phases)


def _fail_artifact(root, valid_report, artifact, invalid, cmd, **kwargs):
    report = deepcopy(valid_report)
    if artifact == "report":
        report["findings"] = "not-an-array"
    else:
        _write(invalid, {"invalid": True})
    _write(_report(root), report)
    return subprocess.CompletedProcess(cmd, 4, "", "artifact invalid: schema defect")


def _succeed_retry(root, valid_report, returncode, cmd, **kwargs):
    assert _pending(root).is_file(), "pending attempt must precede the child"
    assert not Path(str(_pending(root)) + ".tmp").exists()
    _write(_report(root), valid_report)
    return subprocess.CompletedProcess(cmd, returncode, "", "")


@pytest.mark.parametrize("artifact", ["report", "x0x"])
def test_failed_artifact_is_retried_on_real_driver_resume(review, artifact):
    root, manifest, valid_report = review
    invalid = _report(root)
    if artifact == "x0x":
        invalid = invalid.with_name(invalid.stem + "-x0x.json")

    fail = partial(_fail_artifact, root, valid_report, artifact, invalid)
    with mock.patch.object(child, "_run_child", side_effect=fail) as launched:
        first = _resume(root)
        resumed = _resume(root)
    assert first["status"] == "error"
    assert resumed["status"] == "error", resumed
    assert first["advanced"] == resumed["advanced"] == []
    assert launched.call_count == 2
    assert not validate.validate_done(root, manifest)
    schema = (validate_schema.REPORT_SCHEMA if artifact == "report"
              else validate_schema.X0X_SCHEMA)
    assert validate_schema.schema_errors(json.loads(invalid.read_text()), schema)
    if artifact == "x0x":
        assert validate_schema.schema_errors(json.loads(_report(root).read_text())) == []


def test_real_scope_refusal_keeps_old_report_failed_until_repaired(review):
    root, manifest, valid_report = review
    _write(_report(root), valid_report)
    before = _report(root).read_bytes()
    _write(runio._pano(root, "groups.json"), {"groups": []})
    # As in #3192's pin, explicitly execute the phase beside the old report.
    with pytest.raises(runio.DriverError, match="review scope refused"):
        synthesize.synthesize_execute(root, manifest)
    resumed = _resume(root)
    assert resumed["status"] == "error", resumed
    assert "review scope refused" in resumed["message"]
    assert _report(root).read_bytes() == before
    assert not validate.validate_done(root, manifest)
    _write(runio._pano(root, "groups.json"), {"mode": "repo", "groups": []})
    repaired = _resume(root)
    assert repaired["status"] == "complete", repaired
    assert repaired["advanced"] == ["synthesize", "validate"]
    assert not _pending(root).exists()


@pytest.mark.parametrize("returncode", [0, 1, 2])
def test_accepted_retry_clears_pending_once_and_preserves_gate_outcomes(review, returncode):
    root, manifest, valid_report = review
    _write(_pending(root), {"run_id": manifest["run_id"]})

    succeed = partial(_succeed_retry, root, valid_report, returncode)
    with mock.patch.object(child, "_run_child", side_effect=succeed) as launched:
        status = _resume(root)
        assert status["status"] == "complete", status
        assert status["advanced"] == ["synthesize", "validate"]
        assert not _pending(root).exists()
        assert synthesize.synthesize_done(root, manifest)
        again = _resume(root)
        assert "already complete" in again["message"]
        assert launched.call_count == 1


@pytest.mark.parametrize("failure", ["launch", "interrupt", "unusable-report"])
def test_pending_survives_child_failure_or_unusable_output(review, failure):
    root, manifest, valid_report = review
    _write(_report(root), valid_report)

    def fail(cmd, **kwargs):
        if failure == "interrupt":
            raise KeyboardInterrupt
        if failure == "launch":
            raise runio.DriverError("synthesize child launch refused")
        _write(_report(root), {"findings": []})
        return subprocess.CompletedProcess(cmd, 0, "", "")

    error = KeyboardInterrupt if failure == "interrupt" else runio.DriverError
    with mock.patch.object(child, "_run_child", side_effect=fail), pytest.raises(error):
        synthesize.synthesize_execute(root, manifest)
    assert _pending(root).is_file()
    assert not synthesize.synthesize_done(root, manifest)


@pytest.mark.parametrize("kind", ["empty", "malformed", "unreadable", "dangling", "directory"])
def test_any_existing_pending_marker_refuses_completion(review, kind, tmp_path):
    root, manifest, valid_report = review
    _write(_report(root), valid_report)
    pending = _pending(root)
    if kind == "dangling":
        pending.symlink_to(tmp_path / "absent")
    elif kind == "directory":
        pending.mkdir()
    else:
        pending.write_text("{" if kind == "malformed" else "", encoding="utf-8")
        if kind == "unreadable":
            pending.chmod(0)
    try:
        assert not synthesize.synthesize_done(root, manifest)
    finally:
        if kind == "unreadable":
            pending.chmod(0o600)


def test_reset_removes_pending_but_preserves_durable_report(review):
    root, manifest, valid_report = review
    _write(_report(root), valid_report)
    _write(_pending(root), {"run_id": manifest["run_id"]})
    pending, report = _pending(root), _report(root)
    driver._clear_run_artifacts(root)
    run_manifest.reset_run(root)
    fresh = _manifest(root)
    assert not pending.exists()
    assert report.is_file()
    assert _pending(root) != pending
    assert not _pending(root).exists()
    assert not synthesize.synthesize_done(root, fresh)


def test_a_marker_stat_failure_is_not_evidence_of_absence(review):
    root, manifest, valid_report = review
    _write(_report(root), valid_report)
    pending = str(_pending(root))
    _write(pending, {"run_id": manifest["run_id"]})
    lstat = os.lstat

    def denied(path, *args, **kwargs):
        if os.fspath(path) == pending:
            raise PermissionError("run directory is not searchable")
        return lstat(path, *args, **kwargs)

    with mock.patch.object(os, "lstat", side_effect=denied):
        assert not synthesize.synthesize_done(root, manifest)


def test_a_different_run_does_not_inherit_pending(review):
    root, manifest, valid_report = review
    _write(_pending(root), {"run_id": manifest["run_id"]})
    previous = _pending(root)
    run_manifest.reset_run(root)
    fresh = _manifest(root)
    _write(_report(root), valid_report)
    assert previous.is_file()
    assert _pending(root) != previous
    assert synthesize.synthesize_done(root, fresh)


@pytest.mark.parametrize("staging", [False, True], ids=["marker", "staging"])
def test_pending_write_refuses_outside_symlink_before_child(review, tmp_path, staging):
    root, manifest, valid_report = review
    _write(_report(root), valid_report)
    victim = tmp_path / "victim.json"
    victim.write_text("keep me", encoding="utf-8")
    planted = Path(str(_pending(root)) + (".tmp" if staging else ""))
    planted.symlink_to(victim)
    with mock.patch.object(child, "_run_child") as launched:
        with pytest.raises(ValueError, match="escapes .panopticon"):
            synthesize.synthesize_execute(root, manifest)
    assert not launched.called
    assert victim.read_text(encoding="utf-8") == "keep me"
    assert planted.is_symlink()


def test_pending_removal_refuses_a_parent_redirected_outside(review, tmp_path):
    root, manifest, valid_report = review
    pending = _pending(root)
    _write(pending, {"run_id": manifest["run_id"]})
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / pending.name
    victim.write_text("keep me", encoding="utf-8")

    def redirect(cmd, **kwargs):
        _write(_report(root), valid_report)
        pending.parent.rename(tmp_path / "saved-run")
        pending.parent.symlink_to(outside, target_is_directory=True)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    with mock.patch.object(child, "_run_child", side_effect=redirect):
        with pytest.raises(ValueError, match="escapes .panopticon"):
            synthesize.synthesize_execute(root, manifest)
    assert victim.read_text(encoding="utf-8") == "keep me"
    assert os.path.lexists(pending)


def test_pending_write_failure_stops_before_the_child(review):
    root, _manifest, _valid_report = review
    write_json = runio._write_json

    def fail_pending(path, document, **kwargs):
        if Path(path) == _pending(root):
            raise OSError("marker disk full")
        return write_json(path, document, **kwargs)

    with mock.patch.object(runio, "_write_json", side_effect=fail_pending), \
            mock.patch.object(child, "_run_child") as launched:
        status = _resume(root)
    assert status["status"] == "error", status
    assert "marker disk full" in status["message"]
    assert not launched.called


def test_pending_clear_failure_keeps_the_run_in_error(review):
    root, manifest, valid_report = review

    def succeed(cmd, **kwargs):
        _write(_report(root), valid_report)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    with mock.patch.object(child, "_run_child", side_effect=succeed), \
            mock.patch.object(safe_write, "remove_artifact", side_effect=OSError("marker read only")):
        status = _resume(root)
    assert status["status"] == "error", status
    assert "marker read only" in status["message"]
    assert _pending(root).is_file()
    assert not synthesize.synthesize_done(root, manifest)
