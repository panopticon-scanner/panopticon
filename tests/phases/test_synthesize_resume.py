"""#2930: a failed synthesis attempt cannot become complete on plain resume."""
import contextlib
from copy import deepcopy
import errno
from functools import partial
import io
import json
import os
from pathlib import Path
import subprocess
from unittest import mock

import pytest

import scripts.driver as driver
import scripts.phases.run_artifacts as run_artifacts
import scripts.run_manifest as run_manifest
import scripts.safe_glob as safe_glob
import scripts.safe_write as safe_write
import scripts.synthesize as synthesize_cli
from scripts.phases import child, engine, runio, synthesize, validate
from scripts.synth import validate_schema
from tests._test_helpers import adopt_panopticon, our_manifest
from tests.tools.git_repo import make_git_repo


def _write(path, document):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")


def _pending(root):
    return Path(runio._pano(root, "synthesize-pending.json"))


def _report(root):
    return Path(runio._report_out(root))


def _aside(root, path):
    """Where the driver moves `path`, a file an earlier attempt published (#3769)."""
    return Path(runio._pano(root, "earlier-attempt")) / Path(path).name


def _published(root):
    """Every file the synthesize child can publish for this run's report."""
    report = _report(root)
    x0x = report.with_name(report.stem + "-x0x.json")
    return {"report": report, "page": Path(str(report) + ".html"), "x0x": x0x,
            "x0x failures": x0x.with_name(x0x.stem + "-failures.json")}


def _flat(root):
    """The two flat names a reader of "the latest report" opens."""
    return {"report": Path(runio._pano(root, "report.json")),
            "page": Path(runio._pano(root, "report.json.html"))}


@contextlib.contextmanager
def _lstat_fails(root, path, look, reason=(errno.EIO, "Input/output error")):
    """From the moment this attempt's marker is written, the `look`th `os.lstat` of
    `path` fails."""
    real_lstat, real_write, pending = os.lstat, runio._write_json, _pending(root)
    armed, looks = [], []

    def write(target, document, **kwargs):
        written = real_write(target, document, **kwargs)
        if Path(target) == pending:
            armed.append(True)
        return written

    def lstat(target, *args, **kwargs):
        if armed and os.fspath(target) == str(path):
            looks.append(True)
            if len(looks) == look:
                raise OSError(*reason)
        return real_lstat(target, *args, **kwargs)

    with mock.patch.object(runio, "_write_json", side_effect=write), \
            mock.patch.object(os, "lstat", side_effect=lstat):
        yield


def _manifest(root):
    adopt_panopticon(root)           # #3271: a run of OURS, resuming
    manifest = run_manifest.build_manifest(
        target=root, review_root=root, host="codex", security_mode="standard",
        flags={"tools": False}, scope={"mode": "repo", "target": None})
    run_manifest.write_manifest(root, our_manifest(root, manifest))
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
    assert not os.path.lexists(_report(root))            # #3769: kept, and not as the report
    assert _aside(root, _report(root)).read_bytes() == before
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
    run_artifacts._clear_run_artifacts(root)
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


def test_a_retry_the_child_refuses_does_not_pass_off_the_earlier_report(review):
    """#3706 five gates at 590d2946, item 1. The synthesize child exits 3 when a
    directory it must list cannot be listed, and writes no report. The driver looked
    only for a usable report on disk, found the one an earlier attempt of this run had
    left, cleared the pending marker and returned `complete`: a stale verdict, certified,
    for an attempt that never produced one."""
    root, manifest, valid_report = review
    # What an earlier attempt of this run left: a usable report, and the marker that
    # says the attempt did not finish.
    _write(_report(root), valid_report)
    _write(_pending(root), {"run_id": manifest["run_id"]})
    before = _report(root).read_bytes()
    flat = Path(runio._pano(root, "report.json"))
    assert not os.path.lexists(flat)
    run_folder = os.path.dirname(runio._pano(root, "verdicts"))
    statuses = []

    def the_child_itself(cmd, **kwargs):
        """The real `synthesize.py`, in this process, with one listing failing under it.
        (A directory that stays unlistable never gets this far: first contact, the
        driver's and the child's own, refuses it by name.)"""
        real_under = safe_glob.under

        def under(directory, *parts):
            if os.path.realpath(directory) == os.path.realpath(run_folder):
                raise safe_glob.Unlistable(directory, PermissionError(
                    errno.EACCES, "Permission denied"))
            return real_under(directory, *parts)

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(safe_glob, "under", under), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            statuses.append(synthesize_cli.main(cmd[2:]))
        return subprocess.CompletedProcess(cmd, statuses[-1], out.getvalue(), err.getvalue())

    with mock.patch.object(child, "_run_child", side_effect=the_child_itself):
        refused = _resume(root)
    assert statuses == [3]
    assert refused["status"] == "error", refused
    assert refused["message"].endswith(
        "synthesize wrote no report (rc=3): synthesize: %s could not be listed: "
        "Permission denied" % run_folder), refused["message"]
    assert refused["advanced"] == []
    assert _pending(root).is_file()                      # the attempt is still owed
    assert not synthesize.synthesize_done(root, manifest)
    assert not validate.validate_done(root, manifest)
    assert not os.path.lexists(_report(root))            # and the old report is only old:
    assert _aside(root, _report(root)).read_bytes() == before        # set aside (#3769),
    assert not os.path.lexists(flat)                     # with nothing pointed at it
    repaired = _resume(root)
    assert repaired["status"] == "complete", repaired
    assert repaired["advanced"] == ["synthesize", "validate"]
    assert not _pending(root).exists()


@pytest.mark.parametrize("returncode", [3, 5, 70, -9, 255])
def test_a_child_status_that_publishes_nothing_is_an_error_beside_an_old_report(review, returncode):
    """Only the statuses the child returns after publishing (the three gate outcomes,
    and 4 for an artifact that failed validation) may be followed by a look for a
    report. The reason given is the child's last line, on one line."""
    root, manifest, valid_report = review
    _write(_report(root), valid_report)
    before = _report(root).read_bytes()
    said = "synthesize: warming up\n\nsynthesize: no such thing to read\n\n"

    def died(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, returncode, "", said)

    with mock.patch.object(child, "_run_child", side_effect=died), \
            pytest.raises(runio.DriverError) as refused:
        synthesize.synthesize_execute(root, manifest)
    assert str(refused.value) == ("synthesize wrote no report (rc=%s): "
                                  "synthesize: no such thing to read" % returncode)
    assert _pending(root).is_file()
    assert not os.path.lexists(_report(root))
    assert _aside(root, _report(root)).read_bytes() == before
    assert not os.path.lexists(runio._pano(root, "report.json"))
    assert not synthesize.synthesize_done(root, manifest)


def test_a_child_that_died_silently_still_gets_a_reason(review):
    root, manifest, valid_report = review
    _write(_report(root), valid_report)
    token = "ghp_" + "A" * 36
    for stdout, stderr, said in (("", "", "it said nothing"), ("on stdout\n", "", "on stdout"),
                                 ("on stdout\n", " \n", "on stdout"),
                                 ("on stdout\n", "on stderr\n", "on stderr"),
                                 # Redacted and bounded, like every child line the driver relays.
                                 ("", "first\nread %s\n" % token, "read [REDACTED_TOKEN]"),
                                 ("", "x" * 500, "x" * 400)):
        with mock.patch.object(child, "_run_child", return_value=subprocess.CompletedProcess(
                [], 3, stdout, stderr)), pytest.raises(runio.DriverError) as refused:
            synthesize.synthesize_execute(root, manifest)
        assert str(refused.value) == "synthesize wrote no report (rc=3): %s" % said


def _the_real_child(cmd, **kwargs):
    """The real `synthesize.py`, run in this process as the driver's child."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = synthesize_cli.main(cmd[2:])
    return subprocess.CompletedProcess(cmd, status, out.getvalue(), err.getvalue())


def _an_attempt_that_published_and_is_still_owed(root):
    """A first attempt, through the driver: the real child publishes, the driver points
    the flat paths at its report, and then cannot clear its marker."""
    remove = safe_write.remove_artifact

    def keep_the_marker(path):
        if Path(path) == _pending(root):
            raise OSError("marker read only")
        return remove(path)

    with mock.patch.object(child, "_run_child", side_effect=_the_real_child), \
            mock.patch.object(safe_write, "remove_artifact", side_effect=keep_the_marker):
        first = _resume(root)
    assert first["status"] == "error" and "marker read only" in first["message"], first
    assert _pending(root).is_file()


@pytest.mark.parametrize("returncode", [0, 1, 2, 3, 4, -9, "timed out"])
def test_a_retry_that_dies_without_writing_is_not_given_the_earlier_report(review, returncode):
    """#3769. A synthesize child that dies before it publishes can exit with any status:
    an uncaught exception is 1, a usage refusal 2, a scope refusal 4, and those are also
    what a gate FAIL, an INCONCLUSIVE and an invalid artifact exit with. The driver looked
    for a usable report on disk, found the one an earlier attempt had published, and for
    0, 1 and 2 cleared the marker and ended the run `complete` on it; for 4 it pointed
    the flat paths at it."""
    root, manifest, _valid_report = review
    _an_attempt_that_published_and_is_still_owed(root)
    published = _published(root)
    _write(published["x0x failures"], {"discarded_findings": [{"left": "by that attempt"}]})
    before = {name: path.read_bytes() for name, path in published.items()}
    flat = _flat(root)
    for name, link in flat.items():
        assert link.resolve() == published[name].resolve()
    assert not os.path.lexists(runio._pano(root, "earlier-attempt"))

    if returncode == "timed out":                        # as `child._run_child` reports one
        died = mock.patch.object(child, "_run_child", side_effect=runio.DriverError(
            "synthesize: synthesize.py timed out after 1800s"))
        said = ["synthesize: synthesize.py timed out after 1800s"]
    else:
        died = mock.patch.object(child, "_run_child", return_value=subprocess.CompletedProcess(
            [], returncode, "", "Traceback (most recent call last):\nRuntimeError: it broke\n"))
        said = ["(rc=%s)" % returncode, "RuntimeError: it broke"]
    with died as launched:
        retried = _resume(root)
    assert launched.call_count == 1
    assert retried["status"] == "error", retried
    assert all(part in retried["message"] for part in said), retried["message"]
    assert retried["advanced"] == []
    assert _pending(root).is_file()                      # the attempt is still owed
    assert not synthesize.synthesize_done(root, manifest)
    assert not validate.validate_done(root, manifest)
    for name, path in published.items():                 # kept, and not as this run's report
        assert not os.path.lexists(path), name
        assert _aside(root, path).read_bytes() == before[name], name
    for name, link in flat.items():                      # the flat paths are gone
        assert not os.path.lexists(link), name

    with mock.patch.object(child, "_run_child", side_effect=_the_real_child):
        repaired = _resume(root)
    assert repaired["status"] == "complete", repaired
    assert repaired["advanced"] == ["synthesize", "validate"]
    assert not _pending(root).exists()
    for name, link in flat.items():
        assert link.resolve() == published[name].resolve() and link.is_file(), name
    assert not os.path.lexists(published["x0x failures"])


def test_a_later_set_aside_replaces_the_one_before_it(review):
    root, manifest, valid_report = review
    _write(_pending(root), {"run_id": manifest["run_id"]})
    died = subprocess.CompletedProcess([], 1, "", "it broke")
    for attempt in ("first", "second"):
        _write(_report(root), dict(valid_report, left_by=attempt))
        left = _report(root).read_bytes()
        with mock.patch.object(child, "_run_child", return_value=died):
            assert _resume(root)["status"] == "error"
        assert not os.path.lexists(_report(root))
        assert _aside(root, _report(root)).read_bytes() == left


@pytest.mark.parametrize("owed", [True, False], ids=["owed", "unusable"])
def test_a_report_that_cannot_be_set_aside_stops_the_attempt_before_the_child(review, owed):
    root, manifest, valid_report = review
    if owed:
        _write(_report(root), valid_report)
        _write(_pending(root), {"run_id": manifest["run_id"]})
    else:                                                # no marker yet: this attempt writes it
        _write(_report(root), {"findings": []})
    before = _report(root).read_bytes()
    in_the_way = _aside(root, _report(root))
    _write(in_the_way / "something", {})                 # a directory that is not empty
    with mock.patch.object(child, "_run_child") as launched:
        stopped = _resume(root)
    assert stopped["status"] == "error", stopped
    assert ("synthesize could not set aside an earlier attempt's %s: " % _report(root).name
            in stopped["message"])
    assert "still there" not in stopped["message"]       # the move's own reason
    assert not launched.called
    assert _pending(root).is_file()                      # written first: the attempt is owed
    assert _report(root).read_bytes() == before
    assert not synthesize.synthesize_done(root, manifest)


@pytest.mark.parametrize("failing", ["the look", "the removal", "the move"])
def test_the_reason_a_name_could_not_be_cleared_is_redacted_and_bounded(review, failing):
    root, manifest, valid_report = review
    _write(_pending(root), {"run_id": manifest["run_id"]})
    token = "ghp_" + "A" * 36
    replace, remove, flat = os.replace, safe_write.remove_artifact, _flat(root)["report"]
    for reason, said in (("read %s" % token, "read [REDACTED_TOKEN]"), ("x" * 500, "x" * 400)):
        _write(_report(root), valid_report)
        if not os.path.lexists(flat):
            flat.symlink_to(_report(root).name)

        def refuse_move(source, destination, **kwargs):
            if Path(source) == _report(root):
                raise OSError(reason)
            return replace(source, destination, **kwargs)

        def refuse_removal(path):
            if Path(path) == flat:
                raise OSError(reason)
            return remove(path)

        fault, message = {
            "the look": (_lstat_fails(root, _report(root), 1, (reason,)),
                         "synthesize could not look at %s: %s" % (_report(root).name, said)),
            "the removal": (mock.patch.object(safe_write, "remove_artifact", refuse_removal),
                            "synthesize could not remove the flat report.json: %s" % said),
            "the move": (mock.patch.object(os, "replace", side_effect=refuse_move),
                         "synthesize could not set aside an earlier attempt's %s: %s"
                         % (_report(root).name, said)),
        }[failing]
        with fault, mock.patch.object(child, "_run_child") as launched:
            stopped = _resume(root)
        assert stopped["message"].endswith(message), stopped["message"]
        assert not launched.called


@pytest.mark.parametrize("returncode", [0, 1, 2])
@pytest.mark.parametrize("target", ["a report elsewhere", "nothing"])
def test_a_link_at_the_reports_name_is_neither_moved_nor_taken_for_a_report(
        review, tmp_path, target, returncode):
    """Only a regular file is something an attempt published. A link is left for the
    child, which refuses it by name, and the report it leads to is not this attempt's.
    First contact refuses such a link when a run starts, so this is one that appears
    during the run."""
    root, manifest, valid_report = review
    _write(_pending(root), {"run_id": manifest["run_id"]})
    elsewhere = tmp_path / "elsewhere.json"
    if target == "a report elsewhere":
        _write(elsewhere, valid_report)
    _report(root).symlink_to(elsewhere)
    died = subprocess.CompletedProcess([], returncode, "", "it broke")
    with mock.patch.object(child, "_run_child", return_value=died), \
            pytest.raises(runio.DriverError, match="produced no usable report.json"):
        synthesize.synthesize_execute(root, manifest)
    assert os.readlink(_report(root)) == str(elsewhere)
    assert not os.path.lexists(_aside(root, _report(root)).parent)
    assert elsewhere.exists() == (target == "a report elsewhere")
    assert _pending(root).is_file()
    assert not os.path.lexists(runio._pano(root, "report.json"))


def test_a_move_that_leaves_the_report_in_place_stops_the_attempt_before_the_child(review):
    """The run folder's `earlier-attempt` as a link back to `.panopticon/`: the move is
    then onto the report itself, which succeeds and moves nothing. First contact
    refuses such a link when a run starts, so this is one that appears during the run."""
    root, manifest, valid_report = review
    _write(_report(root), valid_report)
    _write(_pending(root), {"run_id": manifest["run_id"]})
    before = _report(root).read_bytes()
    aside = _aside(root, _report(root)).parent
    aside.symlink_to(os.path.join(os.pardir, os.pardir), target_is_directory=True)
    assert aside.resolve() == _report(root).parent.resolve()
    with mock.patch.object(child, "_run_child") as launched, \
            pytest.raises(runio.DriverError) as stopped:
        synthesize.synthesize_execute(root, manifest)
    assert str(stopped.value) == (
        "synthesize could not set aside an earlier attempt's %s: it is still there after "
        "the move to %s" % (_report(root).name, aside))
    assert not launched.called
    assert _pending(root).is_file()
    assert _report(root).read_bytes() == before


def test_setting_aside_refuses_a_run_folder_entry_redirected_outside(review, tmp_path):
    root, manifest, valid_report = review
    _write(_report(root), valid_report)
    _write(_pending(root), {"run_id": manifest["run_id"]})
    before = _report(root).read_bytes()
    outside = tmp_path / "outside"
    outside.mkdir()
    _aside(root, _report(root)).parent.symlink_to(outside, target_is_directory=True)
    with mock.patch.object(child, "_run_child") as launched, \
            pytest.raises(ValueError, match="escapes .panopticon"):
        synthesize.synthesize_execute(root, manifest)       # as the marker's own refusals
    assert not launched.called
    assert list(outside.iterdir()) == []
    assert _report(root).read_bytes() == before


@pytest.mark.parametrize("returncode", [0, 1, 2, 3, 4, -9])
def test_a_new_run_whose_synthesis_dies_leaves_no_flat_path_on_the_run_before(review, returncode):
    """#3778. Run A completes and the flat paths point at its report. Run B's first
    synthesis dies without writing: the flat paths stayed on A's report, beside B's
    `error`, so a reader of `.panopticon/report.json` read another run's verdict."""
    root, _manifest_a, _valid_report = review
    with mock.patch.object(child, "_run_child", side_effect=_the_real_child):
        assert _resume(root)["status"] == "complete"
    of_a = {name: path for name, path in _published(root).items() if path.exists()}
    before = {name: path.read_bytes() for name, path in of_a.items()}
    assert set(of_a) == {"report", "page", "x0x"}
    flat = _flat(root)
    for name, link in flat.items():
        assert link.resolve() == of_a[name].resolve()

    run_manifest.reset_run(root)
    manifest_b = _manifest(root)
    assert _report(root) != of_a["report"]
    died = subprocess.CompletedProcess([], returncode, "", "it broke")
    with mock.patch.object(child, "_run_child", return_value=died) as launched:
        failed = _resume(root)
    assert launched.call_count == 1
    assert failed["status"] == "error", failed
    assert not synthesize.synthesize_done(root, manifest_b)
    for name, link in flat.items():                      # not A's verdict, and not anything
        assert not os.path.lexists(link), name
    for name, path in of_a.items():                      # A's own files are A's still
        assert path.read_bytes() == before[name], name
    assert not os.path.lexists(runio._pano(root, "earlier-attempt"))

    with mock.patch.object(child, "_run_child", side_effect=_the_real_child):
        assert _resume(root)["status"] == "complete"
    for name, link in flat.items():
        assert link.resolve() == _published(root)[name].resolve() and link.is_file(), name
    for name, path in of_a.items():
        assert path.read_bytes() == before[name], name


def test_a_flat_link_that_cannot_be_removed_stops_the_attempt_before_anything_is_moved(review):
    root, manifest, _valid_report = review
    _an_attempt_that_published_and_is_still_owed(root)
    published, flat = _published(root), _flat(root)
    before = published["report"].read_bytes()
    remove = safe_write.remove_artifact

    def refuse(path):
        if Path(path) == flat["page"]:
            raise OSError(errno.EROFS, "Read-only file system")
        return remove(path)

    with mock.patch.object(safe_write, "remove_artifact", side_effect=refuse), \
            mock.patch.object(child, "_run_child") as launched:
        stopped = _resume(root)
    assert stopped["status"] == "error", stopped
    assert stopped["message"].endswith(
        "synthesize could not remove the flat report.json.html: "
        "[Errno 30] Read-only file system"), stopped["message"]
    assert not launched.called
    assert _pending(root).is_file()
    assert published["report"].read_bytes() == before        # nothing was moved
    assert not os.path.lexists(runio._pano(root, "earlier-attempt"))
    assert not os.path.lexists(flat["report"])               # the one before it is gone


def test_a_regular_file_at_a_flat_name_is_set_aside_too(review):
    """What a pre-5.1 run left: `report.json` as a file, not a link to a tag-named one."""
    root, manifest, valid_report = review
    flat = _flat(root)
    _write(flat["report"], valid_report)
    flat["page"].write_text("<html>an old page</html>", encoding="utf-8")
    before = {name: path.read_bytes() for name, path in flat.items()}
    died = subprocess.CompletedProcess([], 1, "", "it broke")
    with mock.patch.object(child, "_run_child", return_value=died):
        assert _resume(root)["status"] == "error"
    for name, path in flat.items():
        assert not os.path.lexists(path), name
        assert _aside(root, path).read_bytes() == before[name], name


@pytest.mark.parametrize("kind", ["absent", "a directory"])
@pytest.mark.parametrize("odd", ["report", "page", "x0x", "x0x failures"])
def test_each_file_of_an_earlier_attempt_is_set_aside_whatever_the_others_are(review, odd, kind):
    """One name with nothing at it, or with something that is not a file, does not
    decide for the names after it, and the report does not decide for its companions."""
    root, manifest, _valid_report = review
    _write(_pending(root), {"run_id": manifest["run_id"]})
    published = _published(root)
    for name, path in published.items():
        if name != odd:
            path.write_bytes(name.encode())
        elif kind == "a directory":
            path.mkdir()
    died = subprocess.CompletedProcess([], 1, "", "it broke")
    with mock.patch.object(child, "_run_child", return_value=died) as launched:
        assert _resume(root)["status"] == "error"
    assert launched.call_count == 1
    for name, path in published.items():
        if name == odd:
            assert path.is_dir() == (kind == "a directory")
            assert not os.path.lexists(_aside(root, path))
        else:
            assert not os.path.lexists(path), name
            assert _aside(root, path).read_bytes() == name.encode(), name


def test_a_move_refused_partway_stops_the_attempt_and_the_next_one_moves_the_rest(review):
    root, manifest, _valid_report = review
    _an_attempt_that_published_and_is_still_owed(root)
    published, flat = _published(root), _flat(root)
    before = {name: path.read_bytes() for name, path in published.items() if path.exists()}
    assert set(before) == {"report", "page", "x0x"}
    replace = os.replace

    def refuse(source, destination, **kwargs):
        if Path(source) == published["page"]:
            raise OSError(errno.ENOSPC, "No space left on device")
        return replace(source, destination, **kwargs)

    with mock.patch.object(os, "replace", side_effect=refuse), \
            mock.patch.object(child, "_run_child") as launched:
        stopped = _resume(root)
    assert stopped["status"] == "error", stopped
    assert stopped["message"].endswith(
        "synthesize could not set aside an earlier attempt's %s: "
        "[Errno 28] No space left on device" % published["page"].name), stopped["message"]
    assert not launched.called
    assert _pending(root).is_file()
    assert not os.path.lexists(published["report"])          # moved before the page was tried
    assert _aside(root, published["report"]).read_bytes() == before["report"]
    assert published["page"].read_bytes() == before["page"]  # where it was, and
    for name, link in flat.items():                          # with no flat path to it
        assert not os.path.lexists(link), name

    died = subprocess.CompletedProcess([], 1, "", "it broke")
    with mock.patch.object(child, "_run_child", return_value=died):
        assert _resume(root)["status"] == "error"
    for name in before:
        assert not os.path.lexists(published[name]), name
        assert _aside(root, published[name]).read_bytes() == before[name], name


@pytest.mark.parametrize("kept", ["report", "page", "x0x", "x0x failures"])
def test_a_move_that_keeps_its_source_stops_the_attempt_for_any_of_the_files(review, kept):
    root, manifest, valid_report = review
    _write(_pending(root), {"run_id": manifest["run_id"]})
    published = _published(root)
    for name, path in published.items():
        path.write_bytes(name.encode())
    replace = os.replace

    def keep(source, destination, **kwargs):
        if Path(source) != published[kept]:
            return replace(source, destination, **kwargs)

    with mock.patch.object(os, "replace", side_effect=keep), \
            mock.patch.object(child, "_run_child") as launched:
        stopped = _resume(root)
    assert stopped["status"] == "error", stopped
    assert stopped["message"].endswith(
        "synthesize could not set aside an earlier attempt's %s: it is still there after "
        "the move to %s" % (published[kept].name, _aside(root, published[kept]).parent))
    assert not launched.called


def test_a_report_with_a_second_name_is_set_aside_like_any_other(review, tmp_path):
    """A hard link to it elsewhere. First contact refuses one when a run starts, so
    this is one that appears during the run."""
    root, manifest, valid_report = review
    _write(_report(root), valid_report)
    _write(_pending(root), {"run_id": manifest["run_id"]})
    before = _report(root).read_bytes()
    os.link(_report(root), tmp_path / "a second name for it")
    died = subprocess.CompletedProcess([], 1, "", "it broke")
    with mock.patch.object(child, "_run_child", return_value=died), \
            pytest.raises(runio.DriverError, match="produced no usable report.json"):
        synthesize.synthesize_execute(root, manifest)
    assert not os.path.lexists(_report(root))
    assert _aside(root, _report(root)).read_bytes() == before


@pytest.mark.parametrize("name", ["page", "x0x", "x0x failures"])
def test_a_link_at_a_companions_name_is_left_for_the_child(review, tmp_path, name):
    """As for the report: only a regular file is something an attempt published."""
    root, manifest, _valid_report = review
    _write(_pending(root), {"run_id": manifest["run_id"]})
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_text("not ours to move", encoding="utf-8")
    link = _published(root)[name]
    link.symlink_to(elsewhere)
    died = subprocess.CompletedProcess([], 1, "", "it broke")
    with mock.patch.object(child, "_run_child", return_value=died), \
            pytest.raises(runio.DriverError, match="produced no usable report.json"):
        synthesize.synthesize_execute(root, manifest)
    assert os.readlink(link) == str(elsewhere)
    assert not os.path.lexists(_aside(root, link).parent)
    assert elsewhere.read_text(encoding="utf-8") == "not ours to move"


@pytest.mark.parametrize("name", ["flat report", "flat page", "report", "page", "x0x",
                                  "x0x failures"])
def test_a_name_that_cannot_be_looked_at_stops_the_attempt_before_the_child(review, name):
    """#3774 five gates, item 2. Only "no such file" means nothing is there. One EIO
    read as "not a file" skipped the move, and the earlier report was then accepted."""
    root, manifest, _valid_report = review
    _an_attempt_that_published_and_is_still_owed(root)
    published, flat = _published(root), _flat(root)
    _write(published["x0x failures"], {"discarded_findings": []})
    before = published["report"].read_bytes()
    paths = dict(published, **{"flat " + key: path for key, path in flat.items()})
    with _lstat_fails(root, paths[name], 1), \
            mock.patch.object(child, "_run_child") as launched:
        stopped = _resume(root)
    assert stopped["status"] == "error", stopped
    assert stopped["message"].endswith(
        "synthesize could not look at %s: [Errno 5] Input/output error" % paths[name].name)
    assert not launched.called
    assert _pending(root).is_file()
    assert not synthesize.synthesize_done(root, manifest)
    if name.startswith("flat"):                              # nothing was moved
        assert published["report"].read_bytes() == before
    else:                                                    # and the flat links went first
        assert not os.path.lexists(flat["report"]) and not os.path.lexists(flat["page"])


@pytest.mark.parametrize("name", ["report", "page"])
def test_a_moved_file_that_cannot_be_looked_for_stops_the_attempt_before_the_child(review, name):
    root, manifest, _valid_report = review
    _an_attempt_that_published_and_is_still_owed(root)
    path = _published(root)[name]
    with _lstat_fails(root, path, 2), mock.patch.object(child, "_run_child") as launched:
        stopped = _resume(root)
    assert stopped["status"] == "error", stopped
    assert stopped["message"].endswith(
        "synthesize could not look at %s: [Errno 5] Input/output error" % path.name)
    assert not launched.called
    assert _pending(root).is_file()


def test_a_fresh_report_that_cannot_be_looked_at_is_an_error_of_its_own(review):
    """The check after the child: an error there is not "no usable report"."""
    root, manifest, valid_report = review
    _write(_pending(root), {"run_id": manifest["run_id"]})

    def wrote(cmd, **kwargs):
        _write(_report(root), valid_report)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    # The first look finds nothing to set aside; the second is the one after the child.
    the_child = mock.patch.object(child, "_run_child", side_effect=wrote)
    with the_child as launched, _lstat_fails(root, _report(root), 2):
        stopped = _resume(root)
    assert launched.call_count == 1
    assert stopped["status"] == "error", stopped
    assert stopped["message"].endswith(
        "synthesize could not look at %s: [Errno 5] Input/output error" % _report(root).name)
    assert stopped["advanced"] == []
    assert _pending(root).is_file()
    assert not os.path.lexists(runio._pano(root, "report.json"))


def test_the_still_there_reason_is_redacted_and_bounded(tmp_path, monkeypatch):
    """#3774 five gates, item 3: the reason names the run folder, which is the
    operator's path. A token-shaped directory name and a long path, as the gate's."""
    token = "ghp_" + "A" * 36
    parent = tmp_path / token / ("d" * 200) / ("e" * 200)
    parent.mkdir(parents=True)
    root = make_git_repo(tmp_path=parent / "target")
    monkeypatch.chdir(root)
    manifest = _manifest(root)
    _write(_report(root), {"summary": {}})
    aside = _aside(root, _report(root)).parent
    aside.symlink_to(os.path.join(os.pardir, os.pardir), target_is_directory=True)
    with mock.patch.object(child, "_run_child") as launched, \
            pytest.raises(runio.DriverError) as stopped:
        synthesize.synthesize_execute(root, manifest)
    assert not launched.called
    start = "synthesize could not set aside an earlier attempt's %s: " % _report(root).name
    assert str(stopped.value).startswith(start + "it is still there after the move to /")
    reason = str(stopped.value)[len(start):]
    assert token not in reason and "[REDACTED_TOKEN]" in reason
    assert len(reason) == 400 < len(str(aside))


# ---- #3779 part 2: one answer for the run's paths, whatever a later read says --------

def _manifest_unreadable_from(arm):
    """Every read of the run manifest fails once `arm` is set: a failed read is "no
    manifest", and a path lookup that made one answered with the flat path."""
    real = run_manifest.load_manifest
    return mock.patch.object(run_manifest, "load_manifest",
                             side_effect=lambda root: None if arm else real(root))


def test_a_manifest_that_cannot_be_read_mid_run_does_not_move_the_report(review):
    """From the five gates on #3774: the output path, the set-aside directory, the
    usability check and the final links each read the manifest again. One failed read
    between them and the child writes the flat path while the driver reads the tagged
    report of an earlier attempt."""
    root, _manifest, valid_report = review
    earlier = dict(valid_report, earlier_attempt=True)
    _write(_report(root), earlier)                     # an earlier attempt's, still owed
    _write(_pending(root), {"run_id": "earlier"})
    tagged, flat = str(_report(root)), runio._pano(root, "report.json")
    arm = []

    def child_then_no_manifest(cmd, **kwargs):
        done = _the_real_child(cmd, **kwargs)
        arm.append(True)                               # every read after the child fails
        return done

    with mock.patch.object(child, "_run_child", side_effect=child_then_no_manifest) as launched, \
            _manifest_unreadable_from(arm):
        status = _resume(root)
    assert status["status"] == "complete", status
    assert launched.call_args.args[0][launched.call_args.args[0].index("--out") + 1] == tagged
    report = json.loads(Path(tagged).read_text(encoding="utf-8"))
    assert "earlier_attempt" not in report             # this attempt's, at the run's own name
    assert os.readlink(flat) == os.path.basename(tagged)
    assert status["artifacts"]["report"] == tagged
    assert json.loads(Path(_aside(root, tagged)).read_text(encoding="utf-8")) == earlier
    assert not os.path.lexists(_pending(root))


def test_a_manifest_that_cannot_be_read_before_the_child_does_not_send_it_to_the_flat_path(review):
    root, _manifest, _valid_report = review
    tagged = str(_report(root))
    arm = []
    looked = engine.Phase("arm", "deterministic", lambda *_: bool(arm),
                          lambda *_: arm.append(True) or engine.PhaseResult(
                              kind="advanced", message="armed"))
    phases = [looked,
              engine.Phase("synthesize", "deterministic",
                           synthesize.synthesize_done, synthesize.synthesize_execute)]
    args = driver.parse_cli(["run", root, "--host", "codex", "--no-tools"])
    with mock.patch.object(child, "_run_child", side_effect=_the_real_child) as launched, \
            _manifest_unreadable_from(arm):
        status = driver.run(args, phases=phases)
    assert status["status"] == "complete", status
    cmd = launched.call_args.args[0]
    assert cmd[cmd.index("--out") + 1] == tagged
    assert cmd[cmd.index("--groups") + 1] == os.path.join(
        os.path.dirname(os.path.dirname(tagged)), ".panopticon", "runs",
        os.path.basename(tagged)[:-len("-report.json")], "groups.json")
    assert os.path.isfile(tagged) and not os.path.islink(tagged)
    assert os.path.islink(runio._pano(root, "report.json"))
