"""#3798: the report says how old the scanners' advisory data is, and a run warns before
any agent is dispatched when it is stale or of unknown age.

Three parts: the recorder the image build runs (`tools-image/advisory-data/record.py`),
the reader (`scripts.advisory_data`), and the places the answer goes (the tools
manifest, `meta.coverage.advisory_data`, the two surfaces, the readiness row and the
driver's status)."""
import datetime
import importlib.util
import io
import json
import os
import subprocess
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import pytest

import scripts.advisory_data as advisory_data
import scripts.driver as driver
import scripts.html_report as html_report
import scripts.phases.readiness as readiness
import scripts.phases.readiness_checks as readiness_checks
import scripts.phases.runio as runio
import scripts.run_tools as run_tools
import scripts.scanner_config as scanner_config
import scripts.synth.findings as findings_mod
import scripts.synth.plan as plan_mod
import scripts.synth.render as render
import scripts.synth.report as report_mod
import scripts.synth.tool_axis as tool_axis
import scripts.tools_image as tools_image
import scripts.tools_manifest as tools_manifest

ROOT = Path(__file__).resolve().parents[1]
UTC = datetime.timezone.utc
READ_AT = datetime.datetime(2026, 11, 24, 20, 0, 0, tzinfo=UTC)
MARK = "<script>alert(1)</script>\x1b[2J"


def _record():
    spec = importlib.util.spec_from_file_location(
        "advisory_record", ROOT / "tools-image" / "advisory-data" / "record.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _image_file(**sources):
    """The file as the recorder writes it, every source current unless overridden."""
    found = {"nvd": {"last_modified": "2026-11-23T03:59:10Z", "last_checked": "2026-11-23T04:00:07Z"},
             "trivy": {"updated_at": "2026-11-22T18:14:33Z"},
             "osv": {"ecosystems": {name: "2026-11-23T06:05:11Z"
                                    for name in advisory_data.OSV_ECOSYSTEMS}},
             "rustsec": {"downloaded_at": "2026-11-23T06:04:00Z"},
             "ruby": {"downloaded_at": "2026-11-23T06:04:30Z"}}
    found.update(sources)
    return json.dumps({"schema_version": 1, "recorded_at": "2026-11-23T06:10:00Z",
                       "sources": found})


def _block(**sources):
    return advisory_data.block(advisory_data.parse_image_file(_image_file(**sources)), READ_AT)


CURRENT_LINE = ("NVD 2026-11-23, OSV 2026-11-23, Trivy 2026-11-22, RustSec 2026-11-23, "
                "ruby-advisory-db 2026-11-23")
UNKNOWN_LINE = "NVD unknown, OSV unknown, Trivy unknown, RustSec unknown, ruby-advisory-db unknown"


# --- the recorder (image build) ------------------------------------------------


@pytest.mark.parametrize("value, expected", [
    ("2026-11-22T18:14:33.401234567Z", "2026-11-22T18:14:33Z"),      # Trivy's nanoseconds
    ("2026-11-23T04:00:07Z", "2026-11-23T04:00:07Z"),
    ("2026-11-23T06:00:07+02:00", "2026-11-23T04:00:07Z"),
    ("2026-11-23T02:00:07-0200", "2026-11-23T04:00:07Z"),
    ("2026-11-23T04:00:07Z[UTC]", "2026-11-23T04:00:07Z"),           # as Java prints a zone
    ("2026-11-23 04:00:07", "2026-11-23T04:00:07Z"),                 # no offset reads as UTC
    ("1763870407", "2025-11-23T04:00:07Z"),                          # epoch seconds
    ("1763870407000", "2025-11-23T04:00:07Z"),                       # epoch milliseconds
    ("2026-11-23", None), ("yesterday", None), ("", None), (None, None), (7, None),
    ("2026-13-40T00:00:00Z", None), ("2026-11-23T04:00:07Z; rm -rf /", None),
])
def test_the_recorder_normalises_a_timestamp_or_says_none(value, expected):
    assert _record().normalise(value) == expected


def test_trivy_date_is_its_metadata_updated_at(tmp_path):
    record = _record()
    (tmp_path / "db").mkdir()
    meta = tmp_path / "db" / "metadata.json"
    meta.write_text(json.dumps({"Version": 2, "NextUpdate": "2026-11-23T00:14:33Z",
                                "UpdatedAt": "2026-11-22T18:14:33.401234567Z",
                                "DownloadedAt": "2026-11-23T06:01:00Z"}))
    assert record.trivy_updated_at(str(tmp_path)) == "2026-11-22T18:14:33Z"
    for text, reason in (("not json", "is not JSON"), ("[]", "no readable UpdatedAt"),
                         (json.dumps({"UpdatedAt": "soon"}), "no readable UpdatedAt"),
                         ("x" * (record.MAX_METADATA_BYTES + 1), "is larger than")):
        meta.write_text(text)
        with pytest.raises(record.Unreadable, match=reason):
            record.trivy_updated_at(str(tmp_path))
    meta.unlink()
    with pytest.raises(record.Unreadable, match="cannot read"):
        record.trivy_updated_at(str(tmp_path))


def _stamp_file(path, when):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_bytes(b"PK data")
    os.utime(path, (when.timestamp(), when.timestamp()))


def test_osv_date_is_each_ecosystem_archives_download_time(tmp_path):
    record = _record()
    _stamp_file(tmp_path / "osv-scanner" / "npm" / "all.zip", datetime.datetime(2026, 11, 23, 6, 5, 11, tzinfo=UTC))
    _stamp_file(tmp_path / "osv-scanner" / "PyPI" / "all.zip", datetime.datetime(2026, 11, 21, 6, 5, 0, tzinfo=UTC))
    (tmp_path / "osv-scanner" / "Go").mkdir()                       # no archive: not listed
    (tmp_path / "osv-scanner" / "Maven").mkdir()
    (tmp_path / "osv-scanner" / "Maven" / "all.zip").write_bytes(b"")   # empty: not a database
    assert record.osv_downloaded_at(str(tmp_path)) == {
        "PyPI": "2026-11-21T06:05:00Z", "npm": "2026-11-23T06:05:11Z"}
    with pytest.raises(record.Unreadable, match="cannot list"):
        record.osv_downloaded_at(str(tmp_path / "absent"))
    (tmp_path / "empty" / "osv-scanner").mkdir(parents=True)
    with pytest.raises(record.Unreadable, match="no ecosystem database"):
        record.osv_downloaded_at(str(tmp_path / "empty"))


def test_rustsec_and_ruby_dates_are_download_times(tmp_path):
    record = _record()
    rust = tmp_path / "advisory-db"
    (rust / "crates").mkdir(parents=True)
    os.utime(rust, (1763870407, 1763870407))
    assert record.rustsec_downloaded_at(str(rust)) == "2025-11-23T04:00:07Z"
    for missing in (tmp_path / "absent", tmp_path / "hollow"):
        (tmp_path / "hollow").mkdir(exist_ok=True)
        with pytest.raises(record.Unreadable, match="no advisory database"):
            record.rustsec_downloaded_at(str(missing))
    ruby = tmp_path / "ruby-advisory-db"
    (ruby / ".git").mkdir(parents=True)
    os.utime(ruby / ".git", (1763870000, 1763870000))
    assert record.ruby_downloaded_at(str(ruby)) == "2025-11-23T03:53:20Z"      # no fetch yet: the clone
    _stamp_file(ruby / ".git" / "FETCH_HEAD", datetime.datetime(2026, 11, 23, 6, 4, 30, tzinfo=UTC))
    assert record.ruby_downloaded_at(str(ruby)) == "2026-11-23T06:04:30Z"      # the last fetch wins
    with pytest.raises(record.Unreadable, match="no fetched advisory database"):
        record.ruby_downloaded_at(str(tmp_path / "absent"))


def _dependency_check(tmp_path, properties="data.user=dcuser\ndata.password=secret-default\n"):
    home, data = tmp_path / "dependency-check", tmp_path / "odc-data"
    (home / "lib").mkdir(parents=True)
    data.mkdir()
    (home / "lib" / "h2-2.1.214.jar").write_bytes(b"jar")
    with zipfile.ZipFile(home / "lib" / "dependency-check-core-10.0.3.jar", "w") as jar:
        jar.writestr("dependencycheck.properties", "# defaults\n" + properties)
    (data / "odc.mv.db").write_bytes(b"H2 database bytes")
    return str(home), str(data)


def _h2(rows, returncode=0, seen=None):
    def runner(argv, **kwargs):
        if seen is not None:
            seen.append((list(argv), kwargs))
            url = argv[argv.index("-url") + 1]
            copy = url[len("jdbc:h2:file:"):].split(";")[0] + ".mv.db"
            seen.append(("copy held", Path(copy).read_bytes()))
        text = "ID                    | VALUE\n" + "".join(
            "%s | %s\n" % row for row in rows) + "(%d rows, 3 ms)\n" % len(rows)
        return subprocess.CompletedProcess(argv, returncode, text, "")
    return runner


def test_nvd_dates_are_read_from_a_copy_of_the_database(tmp_path):
    """#451: dependency-check opens its database read-write and blocks on a lock. The
    recorder runs as root in the build, so it never opens the real file: it reads a copy,
    read-only, with the login from the release's own jar, and leaves nothing behind."""
    record = _record()
    home, data = _dependency_check(tmp_path)
    seen = []
    found = record.nvd_properties(home, data, runner=_h2(
        [("nvd.api.last.checked", "1763870407"), ("nvd.api.last.modified", "2026-11-23T03:59:10Z")],
        seen=seen), scratch=str(tmp_path))
    assert found == {"last_modified": "2026-11-23T03:59:10Z", "last_checked": "2025-11-23T04:00:07Z"}
    argv, kwargs = seen[0]
    assert argv[:4] == ["java", "-cp", os.path.join(home, "lib", "h2-2.1.214.jar"), "org.h2.tools.Shell"]
    url = argv[argv.index("-url") + 1]
    assert url.endswith(";ACCESS_MODE_DATA=r")
    assert not url.startswith("jdbc:h2:file:" + data)               # never the real database
    assert argv[argv.index("-user") + 1:argv.index("-user") + 4] == ["dcuser", "-password", "secret-default"]
    # `SELECT *`: `value` is a reserved word in H2 2.x. Naming it was a syntax error the
    # shell printed on stdout with exit 0, and the first real build recorded NVD as null.
    assert argv[-1] == ("SELECT * FROM properties WHERE id IN "
                        "('nvd.api.last.modified', 'nvd.api.last.checked')")
    assert "value" not in argv[-1].lower().replace("select * from properties where id in", "")
    assert kwargs["timeout"] and kwargs["check"] is False
    assert seen[1] == ("copy held", b"H2 database bytes")
    assert sorted(os.listdir(data)) == ["odc.mv.db"]                 # no lock, no trace file
    assert sorted(os.listdir(tmp_path)) == ["dependency-check", "odc-data"]   # the copy is gone


def test_an_nvd_database_that_cannot_be_read_is_named(tmp_path):
    record = _record()
    home, data = _dependency_check(tmp_path)
    rows = [("nvd.api.last.modified", "2026-11-23T03:59:10Z")]
    for runner, reason in (
            (_h2(rows, returncode=1), "the H2 shell exited 1"),
            (_h2([("nvd.api.last.checked", "1763870407")]), "no readable nvd.api.last.modified"),
            (_h2([("nvd.api.last.modified", "last tuesday")]), "no readable nvd.api.last.modified"),
            (mock.Mock(side_effect=OSError("no java")), "could not run the H2 shell: OSError"),
            (mock.Mock(side_effect=subprocess.TimeoutExpired("java", 600)), "could not run the H2 shell"),
            (mock.Mock(return_value=subprocess.CompletedProcess([], 0, "garbage", "")),
             "unexpected H2 shell output: 'garbage'"),
            (mock.Mock(return_value=subprocess.CompletedProcess(
                [], 0, "Error: org.h2.jdbc.JdbcSQLSyntaxErrorException: Syntax error in SQL "
                       "statement \"SELECT id, [*]value\"; expected \"identifier\"\n" + "x" * 500, "")),
             "unexpected H2 shell output: 'Error: org.h2.jdbc.JdbcSQLSyntaxErrorException: Syntax error"),
            (mock.Mock(return_value=subprocess.CompletedProcess([], 0, "", "")),
             "unexpected H2 shell output: ''")):
        with pytest.raises(record.Unreadable, match=reason):
            record.nvd_properties(home, data, runner=runner, scratch=str(tmp_path))
        assert sorted(os.listdir(tmp_path)) == ["dependency-check", "odc-data"]
    os.remove(os.path.join(data, "odc.mv.db"))
    with pytest.raises(record.Unreadable, match="no database at"):
        record.nvd_properties(home, data, runner=_h2(rows))
    os.remove(os.path.join(home, "lib", "h2-2.1.214.jar"))
    (Path(data) / "odc.mv.db").write_bytes(b"x")
    with pytest.raises(record.Unreadable, match="expected one h2 jar, found 0"):
        record.nvd_properties(home, data, runner=_h2(rows))
    other_home, other_data = _dependency_check(tmp_path / "nologin", properties="data.user=dcuser\n")
    with pytest.raises(record.Unreadable, match="no 'data.password' in dependencycheck.properties"):
        record.nvd_properties(other_home, other_data, runner=_h2(rows))


def _whole_image(tmp_path):
    home, data = _dependency_check(tmp_path)
    (tmp_path / "trivy" / "db").mkdir(parents=True)
    (tmp_path / "trivy" / "db" / "metadata.json").write_text(json.dumps({"UpdatedAt": "2026-11-22T18:14:33Z"}))
    _stamp_file(tmp_path / "osv" / "osv-scanner" / "npm" / "all.zip", datetime.datetime(2026, 11, 23, 6, 5, 11, tzinfo=UTC))
    (tmp_path / "rustsec" / "crates").mkdir(parents=True)
    os.utime(tmp_path / "rustsec", (1763870407, 1763870407))
    _stamp_file(tmp_path / "ruby" / ".git" / "FETCH_HEAD", datetime.datetime(2026, 11, 23, 6, 4, 30, tzinfo=UTC))
    return home, data


def test_the_record_holds_every_source_and_one_unreadable_source_does_not_stop_it(tmp_path):
    record = _record()
    home, data = _whole_image(tmp_path)
    rows = [("nvd.api.last.modified", "2026-11-23T03:59:10Z"), ("nvd.api.last.checked", "2026-11-23T04:00:07Z")]
    said = []
    document = record.record(home, data, str(tmp_path / "trivy"), str(tmp_path / "osv"),
                             str(tmp_path / "rustsec"), str(tmp_path / "ruby"),
                             now=datetime.datetime(2026, 11, 23, 6, 10, tzinfo=UTC),
                             runner=_h2(rows), say=said.append)
    assert said == []
    assert document == {
        "schema_version": 1, "recorded_at": "2026-11-23T06:10:00Z",
        "sources": {"nvd": {"last_modified": "2026-11-23T03:59:10Z", "last_checked": "2026-11-23T04:00:07Z"},
                    "trivy": {"updated_at": "2026-11-22T18:14:33Z"},
                    "osv": {"ecosystems": {"npm": "2026-11-23T06:05:11Z"}},
                    "rustsec": {"downloaded_at": "2025-11-23T04:00:07Z"},
                    "ruby": {"downloaded_at": "2026-11-23T06:04:30Z"}}}
    # What the build writes is what the reader reads.
    parsed = advisory_data.parse_image_file(json.dumps(document))
    assert parsed["nvd"] == datetime.datetime(2026, 11, 23, 3, 59, 10, tzinfo=UTC)
    assert parsed["osv_ecosystems"] == {"npm": datetime.datetime(2026, 11, 23, 6, 5, 11, tzinfo=UTC)}
    (tmp_path / "trivy" / "db" / "metadata.json").unlink()
    document = record.record(home, data, str(tmp_path / "trivy"), str(tmp_path / "absent"),
                             str(tmp_path / "rustsec"), str(tmp_path / "ruby"),
                             runner=_h2(rows, returncode=3), say=said.append)
    assert document["sources"]["nvd"] is None and document["sources"]["trivy"] is None
    assert document["sources"]["osv"] is None
    assert document["sources"]["ruby"] == {"downloaded_at": "2026-11-23T06:04:30Z"}
    assert [line.split(":")[0] for line in said] == ["nvd", "trivy", "osv"]
    assert "not recorded: the H2 shell exited 3" in said[0]


@pytest.mark.parametrize("failure, named", [
    # From the shell launch itself, an OS error is already the recorder's own refusal...
    (OSError(28, "No space left on device"), "could not run the H2 shell: OSError"),
    (PermissionError(13, "Permission denied"), "could not run the H2 shell: PermissionError"),
    # ...and output that is not text was not: it escaped and failed the build.
    (UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"), "UnicodeDecodeError: "),
    (ValueError("not text"), "ValueError: not text"),
])
def test_a_source_that_fails_in_any_way_is_null_and_the_build_goes_on(tmp_path, failure, named):
    """#3802 seat review: only the recorder's own `Unreadable` became null. A full disk
    under the database copy, or shell output that is not text, failed the image build,
    and the daily publish depends on it. Every source is recorded or null."""
    record = _record()
    home, data = _whole_image(tmp_path)
    said = []
    document = record.record(home, data, str(tmp_path / "trivy"), str(tmp_path / "osv"),
                             str(tmp_path / "rustsec"), str(tmp_path / "ruby"),
                             runner=mock.Mock(side_effect=failure), say=said.append)
    assert document["sources"]["nvd"] is None
    assert document["sources"]["trivy"] == {"updated_at": "2026-11-22T18:14:33Z"}     # the rest stand
    assert document["sources"]["ruby"] and document["sources"]["rustsec"] and document["sources"]["osv"]
    assert len(said) == 1 and said[0].startswith("nvd: not recorded: " + named)
    with mock.patch.object(record.shutil, "copyfile", side_effect=failure):
        said.clear()
        document = record.record(home, data, str(tmp_path / "trivy"), str(tmp_path / "osv"),
                                 str(tmp_path / "rustsec"), str(tmp_path / "ruby"),
                                 runner=_h2([("nvd.api.last.modified", "2026-11-23T03:59:10Z")]),
                                 say=said.append)
    # The copy of the database: a full disk there is an OSError nothing caught.
    assert document["sources"]["nvd"] is None
    assert said == ["nvd: not recorded: %s: %s" % (type(failure).__name__, failure)]
    with mock.patch.object(record.os, "listdir", side_effect=failure):
        document = record.record(home, data, str(tmp_path / "trivy"), str(tmp_path / "osv"),
                                 str(tmp_path / "rustsec"), str(tmp_path / "ruby"),
                                 runner=_h2([("nvd.api.last.modified", "2026-11-23T03:59:10Z")]),
                                 say=said.append)
    assert document["sources"]["osv"] is None and document["sources"]["rustsec"] is None
    assert document["sources"]["nvd"] == {"last_modified": "2026-11-23T03:59:10Z", "last_checked": None}


def test_the_build_step_writes_the_file_and_prints_what_it_recorded(tmp_path):
    record = _record()
    home, data = _whole_image(tmp_path)
    out_path = tmp_path / "advisory-data.json"
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(record.subprocess, "run", _h2([("nvd.api.last.modified", "2026-11-23T03:59:10Z")])), \
            redirect_stdout(out), redirect_stderr(err):
        code = record.main(["--out", str(out_path), "--dc-home", home, "--nvd-dir", data,
                            "--trivy-cache", str(tmp_path / "trivy"), "--osv-db", str(tmp_path / "osv"),
                            "--rustsec-db", str(tmp_path / "rustsec"), "--ruby-db", str(tmp_path / "ruby")])
    assert code == 0 and err.getvalue() == ""
    written = json.loads(out_path.read_text())
    assert written["sources"]["nvd"] == {"last_modified": "2026-11-23T03:59:10Z", "last_checked": None}
    assert oct(out_path.stat().st_mode & 0o777) == "0o644"
    assert out_path.read_text() in out.getvalue()                    # the build log shows it
    assert advisory_data.block(advisory_data.parse_image_file(out_path.read_bytes()), READ_AT)[
        "sources"]["nvd"]["date"] == "2026-11-23"


def test_the_dockerfile_records_the_dates_after_the_last_data_layer_and_as_root():
    dockerfile = (ROOT / "Dockerfile").read_text()
    step = ("RUN python3 /opt/panopticon/advisory-data-build/record.py "
            "--out %s" % advisory_data.IMAGE_FILE)
    assert "COPY tools-image/advisory-data /opt/panopticon/advisory-data-build" in dockerfile
    assert dockerfile.count(step) == 1
    at = dockerfile.index(step)
    for earlier in ("image --download-db-only", "--experimental-download-offline-databases",
                    "git clone --depth 1 https://github.com/rustsec/advisory-db",
                    "timeout 120 bundle-audit update",
                    "COPY --chown=scanner:scanner --from=nvd-data /opt/odc-data /opt/odc-data"):
        assert dockerfile.index(earlier) < at, earlier
    assert at < dockerfile.index("\nUSER scanner\n")                 # root: it reads /root's Ruby database
    # The recorder's defaults are the paths the image puts each source at.
    recorder = (ROOT / "tools-image" / "advisory-data" / "record.py").read_text()
    for path, default in (("/opt/odc-data", "--nvd-dir"),
                          ("/opt/trivy-cache", "--trivy-cache"), ("/opt/osv-db", "--osv-db"),
                          ("/home/scanner/.cargo/advisory-db", "--rustsec-db"),
                          ("/root/.local/share/ruby-advisory-db", "--ruby-db")):
        assert path in dockerfile
        assert 'add_argument("%s", default="%s")' % (default, path) in recorder
    # dependency-check's zip unpacks to `dependency-check/` under /opt; the adapter's own
    # default home is the same path.
    assert "unzip -q /tmp/dc.zip -d /opt" in dockerfile
    assert 'add_argument("--dc-home", default="/opt/dependency-check")' in recorder
    assert '"DEPENDENCY_CHECK_HOME", "/opt/dependency-check"' in (
        ROOT / "skill" / "scripts" / "tools" / "dependency_check.py").read_text()


# --- the reader ----------------------------------------------------------------


def test_the_file_is_read_to_a_time_per_source_and_the_oldest_osv_ecosystem():
    ecosystems = {name: "2026-11-23T06:05:11Z" for name in advisory_data.OSV_ECOSYSTEMS}
    ecosystems["Maven"] = "2026-11-19T06:05:11Z"
    parsed = advisory_data.parse_image_file(_image_file(osv={"ecosystems": ecosystems}).encode())
    assert parsed["nvd"] == datetime.datetime(2026, 11, 23, 3, 59, 10, tzinfo=UTC)      # last.modified
    assert parsed["trivy"] == datetime.datetime(2026, 11, 22, 18, 14, 33, tzinfo=UTC)
    assert parsed["osv"] == datetime.datetime(2026, 11, 19, 6, 5, 11, tzinfo=UTC)       # the oldest
    assert sorted(parsed["osv_ecosystems"]) == sorted(advisory_data.OSV_ECOSYSTEMS)
    assert parsed["rustsec"] and parsed["ruby"]


@pytest.mark.parametrize("raw", [
    None, 7, b"\xff\xfe", "", "not json", "[]", "null", json.dumps({"schema_version": 1}),
    json.dumps({"schema_version": 2, "sources": {}}), json.dumps({"schema_version": True, "sources": {}}),
    json.dumps({"schema_version": "1", "sources": {}}), json.dumps({"schema_version": 1.0, "sources": {}}),
    json.dumps({"schema_version": 1, "sources": []}), "[" * 5000,
    _image_file() + " " * advisory_data.MAX_FILE_BYTES,
    (_image_file() + " " * advisory_data.MAX_FILE_BYTES).encode(),
])
def test_a_file_that_is_not_the_recorders_reads_as_nothing_and_never_raises(raw):
    parsed = advisory_data.parse_image_file(raw)
    assert parsed == {"nvd": None, "osv": None, "trivy": None, "rustsec": None, "ruby": None,
                      "osv_ecosystems": {}}
    assert advisory_data.line(advisory_data.block(parsed, READ_AT)) == UNKNOWN_LINE


def test_osv_with_an_ecosystem_missing_is_unknown_and_warns():
    """#3802 seat review: the OSV date is the oldest ecosystem's. With one database
    missing the oldest of the REST spoke for it, and the row read `current`. A missing
    ecosystem is data of unknown age."""
    every = {name: "2026-11-23T06:05:11Z" for name in advisory_data.OSV_ECOSYSTEMS}
    whole = _block(osv={"ecosystems": every})
    assert whole["sources"]["osv"]["status"] == "current" and advisory_data.warning(whole) is None
    for missing in advisory_data.OSV_ECOSYSTEMS:
        for broken in ({name: stamp for name, stamp in every.items() if name != missing},
                       dict(every, **{missing: "not a time"}), dict(every, **{missing: None}),
                       dict(every, **{missing: "2031-01-01T00:00:00Z"})):       # not believed
            block = _block(osv={"ecosystems": broken})
            row = block["sources"]["osv"]
            assert (row["date"], row["age_days"], row["status"]) == (None, None, "unknown"), missing
            assert sorted(row["ecosystems"]) == sorted(set(every) - {missing})   # the rest are kept
            assert "OSV unknown" in advisory_data.warning(block)
            assert advisory_data.from_manifest(json.loads(json.dumps(block))) == block
        assert advisory_data.parse_image_file(_image_file(osv={"ecosystems": {
            name: stamp for name, stamp in every.items() if name != missing}}))["osv"] is None
    for none in ({}, None, [], "npm"):
        assert _block(osv={"ecosystems": none})["sources"]["osv"]["status"] == "unknown"
    # A manifest that plants an OSV date beside an incomplete list is not believed.
    planted = json.loads(json.dumps(whole))
    del planted["sources"]["osv"]["ecosystems"]["Maven"]
    assert planted["sources"]["osv"]["date"] == "2026-11-23"
    assert advisory_data.from_manifest(planted)["sources"]["osv"]["status"] == "unknown"
    # One stale ecosystem makes the row stale: it is the oldest.
    old = _block(osv={"ecosystems": dict(every, Go="2026-10-01T00:00:00Z")})
    assert (old["sources"]["osv"]["date"], old["sources"]["osv"]["status"]) == ("2026-10-01", "stale")


@pytest.mark.parametrize("version", [2, 0, True, 1.0, "1", None, [1]])
def test_a_file_of_another_schema_version_is_not_read(version):
    """Only the int 1. `True == 1` and `1.0 == 1`, so the type is checked too: a file whose
    version this reader does not know may mean something else by the same keys."""
    document = json.loads(_image_file())
    assert advisory_data.line(advisory_data.block(
        advisory_data.parse_image_file(json.dumps(document)), READ_AT)) == CURRENT_LINE
    document["schema_version"] = version
    parsed = advisory_data.parse_image_file(json.dumps(document))
    assert advisory_data.line(advisory_data.block(parsed, READ_AT)) == UNKNOWN_LINE


def test_the_size_cap_is_on_the_bytes_the_image_printed():
    """`head -c` bounds what the launch prints, in bytes. A file under the cap in
    characters and over it in bytes was cut mid-way by that bound, so it is not read."""
    document = json.loads(_image_file())
    document["padding"] = "\u00e9" * 9000                           # two bytes each
    text = json.dumps(document, ensure_ascii=False)
    assert len(text) < advisory_data.MAX_FILE_BYTES < len(text.encode("utf-8"))
    assert advisory_data.line(advisory_data.block(
        advisory_data.parse_image_file(text.encode("utf-8")), READ_AT)) == UNKNOWN_LINE
    document["padding"] = "x" * 100
    small = json.dumps(document).encode("utf-8")
    assert advisory_data.line(advisory_data.block(
        advisory_data.parse_image_file(small), READ_AT)) == CURRENT_LINE


@pytest.mark.parametrize("value", [
    "2026-11-23", "2026-11-23T04:00:07", "2026-11-23T04:00:07z", "2026-11-23T04:00:07.5Z",
    "2026-11-23T04:00:07+00:00", " 2026-11-23T04:00:07Z", "2026-11-23T04:00:07Z\n", "2026-02-30T00:00:00Z",
    "2014-12-31T23:59:59Z", "1763870407", 1763870407, None, [], {"date": "2026-11-23T04:00:07Z"}, MARK,
])
def test_only_the_recorders_exact_timestamp_is_a_date(value):
    for key, source in (("nvd", {"last_modified": value}), ("trivy", {"updated_at": value}),
                        ("rustsec", {"downloaded_at": value}), ("ruby", {"downloaded_at": value}),
                        ("osv", {"ecosystems": {"npm": value}})):
        block = _block(**{key: source})
        assert block["sources"][key]["status"] == "unknown", key
        assert block["sources"][key]["date"] is None and block["sources"][key]["age_days"] is None


def test_what_the_reader_does_not_know_is_dropped_and_nothing_of_the_file_is_echoed():
    raw = json.dumps({"schema_version": 1, "recorded_at": MARK, MARK: MARK, "sources": {
        MARK: {"updated_at": "2026-11-23T04:00:07Z"}, "trivy": {"updated_at": MARK, MARK: MARK},
        "nvd": [MARK], "rustsec": MARK, "ruby": {"downloaded_at": "2026-11-23T06:04:30Z", "note": MARK},
        "osv": {"ecosystems": {MARK: "2026-11-23T06:05:11Z", "npm": "2026-11-23T06:05:11Z",
                               "Cargo": "2026-11-23T06:05:11Z"}, MARK: MARK}}})
    block = advisory_data.block(advisory_data.parse_image_file(raw), READ_AT)
    text = json.dumps(block) + advisory_data.line(block) + advisory_data.warning(block)
    for piece in ("script", "alert", "\x1b", "\\u001b", "Cargo"):
        assert piece not in text
    assert block["sources"]["osv"]["ecosystems"] == {"npm": "2026-11-23"}        # the known name only
    assert sorted(block["sources"]) == ["nvd", "osv", "ruby", "rustsec", "trivy"]
    assert block["sources"]["ruby"] == {"date": "2026-11-23", "age_days": 1, "status": "current"}


@pytest.mark.parametrize("stamp, date, age, status", [
    ("2026-11-24T19:59:59Z", "2026-11-24", 0, "current"),
    ("2026-11-23T23:59:59Z", "2026-11-23", 1, "current"),       # counted between dates
    ("2026-11-17T00:00:00Z", "2026-11-17", 7, "current"),       # exactly the threshold: not stale
    ("2026-11-16T23:59:59Z", "2026-11-16", 8, "stale"),
    ("2025-11-24T20:00:00Z", "2025-11-24", 365, "stale"),
    ("2026-11-25T19:59:59Z", "2026-11-25", 0, "current"),       # a clock a little ahead
    ("2026-11-25T20:00:01Z", None, None, "unknown"),            # more than a day ahead: not believed
    ("2031-01-01T00:00:00Z", None, None, "unknown"),
])
def test_the_age_is_whole_days_at_the_read_and_older_than_seven_is_stale(stamp, date, age, status):
    assert advisory_data.STALE_AFTER_DAYS == 7
    block = _block(trivy={"updated_at": stamp})
    assert block["sources"]["trivy"] == {"date": date, "age_days": age, "status": status}
    assert block["read_at"] == "2026-11-24T20:00:00Z" and block["stale_after_days"] == 7


def test_the_line_and_the_warning_are_fixed_sentences():
    current = _block()
    assert advisory_data.line(current) == CURRENT_LINE
    assert advisory_data.warning(current) is None
    behind = _block(trivy={"updated_at": "2026-11-10T18:14:33Z"}, rustsec=None,
                    nvd={"last_modified": "2026-11-23T03:59:10Z"})
    assert advisory_data.line(behind) == ("NVD 2026-11-23, OSV 2026-11-23, Trivy 2026-11-10, "
                                          "RustSec unknown, ruby-advisory-db 2026-11-23")
    assert advisory_data.warning(behind) == (
        "advisory data is older than 7 days or of unknown age: Trivy 2026-11-10 (14 days old); "
        "RustSec unknown. The scanners run offline against the data in the tools image, so a "
        "newer advisory is not reported. Pull or rebuild the image to refresh it. This is a "
        "warning: it does not change the gate or certification")
    one_day = advisory_data.block({"nvd": READ_AT - datetime.timedelta(days=1)}, READ_AT)
    assert "NVD 2026-11-23" in advisory_data.line(one_day)
    assert advisory_data.unread(READ_AT) == advisory_data.block(None, READ_AT)
    assert advisory_data.line(advisory_data.unread(READ_AT)) == UNKNOWN_LINE
    assert advisory_data.warning(advisory_data.unread(READ_AT)).startswith(
        "advisory data is older than 7 days or of unknown age: NVD unknown; OSV unknown; ")
    for nothing in (None, {}, [], "x", {"sources": {}}, {"read_at": "2026-11-24T20:00:00Z"}):
        assert advisory_data.line(nothing) is None and advisory_data.warning(nothing) is None


def test_a_block_from_a_manifest_is_recomputed_and_a_planted_answer_is_not_believed():
    block = _block(osv={"ecosystems": {"npm": "2026-11-23T06:05:11Z", "Go": "2026-11-20T06:05:11Z"}})
    assert advisory_data.from_manifest(json.loads(json.dumps(block))) == block
    planted = json.loads(json.dumps(block))
    planted["sources"]["trivy"] = {"date": "2026-01-01", "age_days": 0, "status": "current"}
    planted["sources"]["nvd"] = {"date": MARK, "age_days": 1, "status": "current"}
    planted["sources"]["ruby"] = MARK
    planted["sources"]["rustsec"]["date"] = "2026-11-23T00:00:00Z"            # not a date: a timestamp
    planted["sources"]["osv"]["ecosystems"] = {"npm": "2026-11-23", MARK: "2026-11-23", "Go": MARK}
    planted["stale_after_days"] = 9999
    planted[MARK] = MARK
    rebuilt = advisory_data.from_manifest(planted)
    assert rebuilt["sources"]["trivy"] == {"date": "2026-01-01", "age_days": 327, "status": "stale"}
    assert rebuilt["sources"]["nvd"]["status"] == "unknown"
    assert rebuilt["sources"]["ruby"]["status"] == "unknown"
    assert rebuilt["sources"]["rustsec"]["status"] == "unknown"
    assert rebuilt["sources"]["osv"]["ecosystems"] == {"npm": "2026-11-23"}
    assert rebuilt["stale_after_days"] == 7 and sorted(rebuilt) == ["read_at", "sources", "stale_after_days"]
    assert "script" not in json.dumps(rebuilt)
    for unusable in (None, [], MARK, {}, {"read_at": MARK, "sources": {}},
                     {"read_at": "2026-11-24T20:00:00Z", "sources": []},
                     dict(block, read_at="2026-11-24")):
        assert advisory_data.from_manifest(unusable) is None


# --- the launch that reads the image --------------------------------------------


def test_the_read_is_one_hardened_launch_with_nothing_mounted():
    flags = scanner_config.privilege_drop_flags()
    argv = advisory_data.read_argv("/usr/bin/docker", "sha256:abc", flags)
    assert argv[:6] == ["/usr/bin/docker", "run", "--rm", "--network", "none", "--read-only"]
    assert "--cap-drop=ALL" in argv and "--security-opt=no-new-privileges" in argv
    for limit in ("--memory", "--memory-swap", "--cpus", "--pids-limit"):
        assert limit in argv
    for absent in ("-v", "--volume", "--mount", "-e", "--env", "--privileged", "-w", "--user", "-u"):
        assert absent not in argv
    assert not [arg for arg in argv if arg.startswith(("--volume=", "--mount=", "--env=", "-v="))]
    image_at = argv.index("sha256:abc")
    assert argv[image_at + 1:] == ["timeout", "20", "head", "-c", str(advisory_data.MAX_FILE_BYTES + 1),
                                   "/opt/panopticon/advisory-data.json"]
    assert advisory_data.READ_TIMEOUT > 20                           # the caller outwaits the container


@pytest.mark.parametrize("returncode, output", [
    (None, None), (1, _image_file()), (124, b""), (0, None), (0, b""), (0, "no such file"), (0, 7),
])
def test_a_launch_that_fails_or_prints_something_else_is_every_source_unknown(returncode, output):
    block = advisory_data.from_launch(returncode, output, READ_AT)
    assert block == advisory_data.unread(READ_AT)
    assert advisory_data.warning(block)


def test_a_launch_that_prints_the_file_is_the_block():
    assert advisory_data.from_launch(0, _image_file().encode(), READ_AT) == _block()
    assert advisory_data.from_launch(0, _image_file(), READ_AT) == _block()
    assert advisory_data.from_launch(0, _image_file())["sources"]["nvd"]["date"] == "2026-11-23"   # now


def test_run_tools_reads_the_image_once_and_can_never_fail_on_it(tmp_path, capsys):
    seen = []

    def runner(argv, **kwargs):
        seen.append((list(argv), kwargs))
        return subprocess.CompletedProcess(argv, 0, _image_file().encode(), b"")
    found = run_tools.read_advisory_data(str(tmp_path), "sha256:abc", runner=runner)
    assert advisory_data.line(found) == advisory_data.line(
        advisory_data.from_launch(0, _image_file()))
    (argv, kwargs), = seen
    assert argv[1:6] == ["run", "--rm", "--network", "none", "--read-only"]
    assert os.path.isabs(argv[0]) and "sha256:abc" in argv
    assert str(tmp_path) not in " ".join(argv)                       # the target is not mounted
    assert kwargs["timeout"] == advisory_data.READ_TIMEOUT
    assert kwargs["stdout"] == subprocess.PIPE and kwargs["stderr"] == subprocess.DEVNULL
    assert "PATH" in kwargs["env"]
    for failure in (subprocess.TimeoutExpired("docker", 30), OSError("gone"),
                    subprocess.SubprocessError("x")):
        found = run_tools.read_advisory_data(str(tmp_path), "sha256:abc",
                                             runner=mock.Mock(side_effect=failure))
        assert advisory_data.line(found) == UNKNOWN_LINE
        assert "advisory-data dates could not be read (%s); reported as unknown" % type(
            failure).__name__ in capsys.readouterr().err
    old_image = mock.Mock(return_value=subprocess.CompletedProcess([], 1, b"", b""))
    assert advisory_data.line(run_tools.read_advisory_data(str(tmp_path), "x", runner=old_image)) == UNKNOWN_LINE


def test_the_manifest_carries_the_block_only_when_it_was_read(tmp_path):
    path = tmp_path / "tools-manifest.json"
    tools_manifest.write_manifest(str(path), ["semgrep"], [], advisory_data=_block())
    assert json.loads(path.read_text())["advisory_data"] == _block()
    tools_manifest.write_manifest(str(path), ["semgrep"], [])
    assert "advisory_data" not in json.loads(path.read_text())


def test_run_tools_main_puts_what_it_read_in_the_manifest(tmp_path):
    manifest = tmp_path / "out" / "manifest.json"
    with mock.patch("scripts.run_tools.docker_available",
                    return_value={"ref": "panopticon-tools", "id": "sha256:abc", "repo_digests": []}), \
            mock.patch("scripts.run_tools.run_tools", return_value=[]), \
            mock.patch("scripts.run_tools.read_advisory_data", return_value=_block()) as read, \
            redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        assert run_tools.main(["--tools", "semgrep", "--target", str(tmp_path),
                               "--out", str(tmp_path / "out"), "--manifest", str(manifest)]) == 0
    read.assert_called_once_with(str(tmp_path), "sha256:abc")
    assert json.loads(manifest.read_text())["advisory_data"] == _block()


# --- the report -----------------------------------------------------------------


def _report(manifest):
    return report_mod.build_report(report_mod.ReportInputs(
        run=report_mod.RunConfig(target="t", fail_on="high", timestamp="2026-11-24T21:00:00Z"),
        findings=findings_mod.FindingSet(findings=[]),
        plan=plan_mod.PlanInputs(groups_meta=[{"name": "Core", "files": ["a.py"]}]),
        tools=tool_axis.ToolAxis(tools_ran=set(), manifest=manifest)))


def _manifest(**extra):
    return dict({"schema_version": 1, "selected": [], "produced": [], "missing": [], "outputs": []},
                **extra)


def test_the_report_carries_the_block_recomputed_and_it_moves_nothing():
    plain = _report(_manifest())
    assert "advisory_data" not in plain["meta"]["coverage"]
    stale = _block(trivy={"updated_at": "2026-10-01T00:00:00Z"}, ruby=None)
    planted = json.loads(json.dumps(stale))
    planted["sources"]["trivy"]["status"] = "current"                # a manifest is not believed
    report = _report(_manifest(advisory_data=planted))
    assert report["meta"]["coverage"]["advisory_data"] == stale
    for key in ("gate", "coverage_certified", "coverage_note", "overall_grade", "health",
                "provisional_grade", "risk_level"):
        assert report["summary"].get(key) == plain["summary"].get(key), key
    assert report["meta"]["integrity"] == plain["meta"]["integrity"]
    without = {k: v for k, v in report["meta"]["coverage"].items() if k != "advisory_data"}
    assert without == plain["meta"]["coverage"]
    assert "advisory_data" not in _report(_manifest(advisory_data=MARK))["meta"]["coverage"]
    assert "advisory_data" not in _report(None)["meta"]["coverage"]


def test_both_surfaces_show_the_dates_and_the_warning_above_them():
    current = _report(_manifest(advisory_data=_block()))
    summary = render.render_summary(current).splitlines()
    assert "**Advisory data:** " + CURRENT_LINE in summary
    assert not [line for line in summary if "Advisory data warning" in line]
    page = html_report.render(current)
    assert page.count("<div class='coverage'>Advisory data: %s</div>" % CURRENT_LINE) == 1
    assert "Advisory data warning" not in page

    stale = _report(_manifest(advisory_data=_block(nvd={"last_modified": "2026-10-01T00:00:00Z"})))
    summary = render.render_summary(stale).splitlines()
    warning = [n for n, line in enumerate(summary) if line.startswith("**Advisory data warning:** advisory data is older than 7 days")]
    dates = [n for n, line in enumerate(summary) if line.startswith("**Advisory data:** NVD 2026-10-01, ")]
    assert len(warning) == 1 and len(dates) == 1 and warning[0] < dates[0] < summary.index("## Groups")
    assert "NVD 2026-10-01 (54 days old)" in summary[warning[0]]
    page = html_report.render(stale)
    assert page.count("Advisory data warning: advisory data is older than 7 days") == 1
    assert page.index("Advisory data warning:") < page.index("Advisory data: NVD 2026-10-01")
    assert "not-certified" not in page[page.index("Advisory data warning:") - 60:page.index("Advisory data warning:")]


def test_a_report_with_no_block_has_neither_line_and_its_page_is_untouched():
    plain = _report(_manifest())
    assert "dvisory data" not in render.render_summary(plain)
    page = html_report.render(plain)
    assert "dvisory data" not in page
    assert html_report._render_advisory_data(plain["meta"]) == []
    with_block = html_report.render(_report(_manifest(advisory_data=_block())))
    line = "<div class='coverage'>Advisory data: %s</div>\n" % CURRENT_LINE
    assert with_block.replace(line, "", 1) == page                  # the one line is all it adds
    # A report from elsewhere, with a block that is not one, prints nothing of it.
    plain["meta"]["coverage"]["advisory_data"] = {"read_at": MARK, "sources": {"nvd": {"date": MARK}}}
    assert "script" not in render.render_summary(plain) and "dvisory data" not in render.render_summary(plain)
    assert "alert(1)" not in html_report.render(plain)


def test_the_page_escapes_both_lines():
    """The two sentences hold nothing to escape today, so the page is the same with and
    without the escape. Pinned on sentences that do: a later edit of the wording, or of
    a label, cannot put markup on the page."""
    report = _report(_manifest(advisory_data=_block(trivy=None)))
    with mock.patch.object(advisory_data, "line", return_value="NVD <b>2026</b> & 'more'"), \
            mock.patch.object(advisory_data, "warning", return_value="<script>alert(1)</script> & \"x\""):
        parts = html_report._render_advisory_data(report["meta"])
        page = html_report.render(report)
    assert parts == [
        "<div class='coverage' role='note'>Advisory data warning: "
        "&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;x&quot;</div>",
        "<div class='coverage'>Advisory data: NVD &lt;b&gt;2026&lt;/b&gt; &amp; &#x27;more&#x27;</div>"]
    assert "<script>alert(1)</script>" not in page and "<b>2026</b>" not in page


def test_the_schema_describes_the_block_the_report_carries():
    import jsonschema
    schema = json.loads((ROOT / "skill" / "reference" / "report-schema.json").read_text())
    node = schema["properties"]["meta"]["properties"]["coverage"]["properties"]["advisory_data"]
    for block in (_block(), advisory_data.unread(READ_AT),
                  _block(trivy={"updated_at": "2026-10-01T00:00:00Z"}, osv={"ecosystems": {"npm": "2026-11-23T06:05:11Z"}})):
        jsonschema.validate(block, node)
    assert node["properties"]["stale_after_days"]["const"] == advisory_data.STALE_AFTER_DAYS
    assert sorted(node["properties"]["sources"]["properties"]) == sorted(
        key for key, _label in advisory_data.SOURCES)
    assert sorted(node["properties"]["sources"]["properties"]["osv"]["properties"]["ecosystems"][
        "properties"]) == sorted(advisory_data.OSV_ECOSYSTEMS)
    for bad in (dict(_block(), extra=1), dict(_block(), stale_after_days=30)):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(bad, node)


# --- the start of the run ---------------------------------------------------------


class _Done:
    def __init__(self, returncode, stdout=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, ""


def _docker(read=None, calls=None):
    """A docker seam: the daemon and the image are there; `read` answers the one launch."""
    def runner(cmd, **kwargs):
        if calls is not None:
            calls.append((list(cmd), kwargs))
        if list(cmd[:2]) == ["docker", "run"]:
            if isinstance(read, BaseException):
                raise read
            return read
        return _Done(0)
    return runner


def test_the_readiness_row_is_the_dates_or_the_warning_and_never_a_failure():
    calls = []
    with mock.patch.object(readiness_checks, "DOCKER_RUNNER", _docker(_Done(0, _image_file()), calls)):
        row = readiness_checks.advisory_data_row(None, True)
    assert row[:2] == ("advisory-data", True)
    assert row[2] == advisory_data.line(advisory_data.from_launch(0, _image_file()))
    (argv, kwargs), = calls
    assert argv == advisory_data.read_argv("docker", tools_image.DEFAULT_IMAGE,
                                           scanner_config.privilege_drop_flags())
    assert kwargs["timeout"] == advisory_data.READ_TIMEOUT
    assert kwargs["text"] is False                  # bytes: this module decodes, and survives
    for raw in (b"\xff\xfe not text", _image_file().encode() + b"\xff"):
        with mock.patch.object(readiness_checks, "DOCKER_RUNNER", _docker(_Done(0, raw))):
            assert readiness_checks.advisory_data_row(None, True)[1] == "warn"
    with mock.patch.object(readiness_checks, "DOCKER_RUNNER", _docker(_Done(0, _image_file().encode()))):
        assert readiness_checks.advisory_data_row(None, True)[1] is True
    # The launch's own bound, not the two probes' (they happen to be equal today).
    waited = []
    with mock.patch.object(advisory_data, "READ_TIMEOUT", 7), \
            mock.patch.object(readiness_checks, "DOCKER_RUNNER", _docker(_Done(0, _image_file()), waited)):
        readiness_checks.advisory_data_row(None, True)
    assert waited[0][1]["timeout"] == 7
    old = _image_file(trivy={"updated_at": "2020-01-01T00:00:00Z"})
    for read in (_Done(0, old), _Done(1), _Done(0, "garbage"), subprocess.TimeoutExpired("docker", 30),
                 OSError("no docker")):
        with mock.patch.object(readiness_checks, "DOCKER_RUNNER", _docker(read)):
            name, ok, detail = readiness_checks.advisory_data_row(True, True)
        assert (name, ok) == ("advisory-data", "warn")
        assert detail.startswith("advisory data is older than 7 days or of unknown age: ")
    launched = mock.Mock()
    with mock.patch.object(readiness_checks, "DOCKER_RUNNER", launched):
        assert readiness_checks.advisory_data_row(False, True) == (
            "advisory-data", None, readiness_checks._NOT_APPLICABLE)     # --no-tools
        assert readiness_checks.advisory_data_row(None, False) == (
            "advisory-data", None, "not read: the tools image is not available")
    launched.assert_not_called()


def test_the_readiness_verb_still_launches_nothing():
    """`driver readiness` promises to start no container. The row belongs to the phase."""
    import inspect
    source = inspect.getsource(readiness)
    phase = source[source.index("def _checks("):source.index("def _refusal(")]
    assert "advisory_data_row" in phase
    assert source.count("advisory_data_row") == 1
    assert "advisory_data" not in inspect.getsource(readiness_checks._tools_image_row)


def _readiness_artifact(root, checks):
    os.makedirs(runio._pano(str(root)), exist_ok=True)
    runio._write_json(runio._pano(str(root), readiness.READINESS),
                      {"schema_version": 1, "ready": True, "checks": checks})


def test_every_status_of_the_run_carries_the_readiness_warnings(tmp_path):
    sentence = advisory_data.warning(advisory_data.unread(READ_AT))
    _readiness_artifact(tmp_path, [
        {"name": "docker", "ok": True, "detail": "ok"},
        {"name": "advisory-data", "ok": None, "detail": sentence, "level": "warn"},
        {"name": "egress-proxy", "ok": None, "detail": "pull the proxy image", "level": "warn"},
        {"name": "host", "ok": None, "detail": "informational, no level"},
        {"name": "bad", "ok": None, "detail": 7, "level": "warn"}, "not a row"])
    expected = ["[advisory-data] " + sentence, "[egress-proxy] pull the proxy image"]
    assert readiness.warnings(str(tmp_path)) == expected
    for status in ({"status": "checkpoint", "checkpoint": "scout", "message": "m"},
                   {"status": "complete", "message": "all phases complete"}):
        assert driver._with_warnings(status, str(tmp_path)) == dict(status, warnings=expected)
        assert "warnings" not in status                               # a copy, not a mutation
    # #3802 seat review: the artifact is in the run folder and the host shows these to
    # a person. Control and direction-override characters are spelled, not carried.
    _readiness_artifact(tmp_path, [{"name": "advisory-data\x1b[2J", "ok": None, "level": "warn",
                                    "detail": "line one\nline two\x07 \u202egnp.exe\x00 done"}])
    (carried,) = readiness.warnings(str(tmp_path))
    assert carried == "[advisory-data\\x1b[2J] line one\\x0aline two\\x07 \\u202egnp.exe\\x00 done"
    assert not [ch for ch in carried if ord(ch) < 32 or ch == "\u202e"]
    assert json.loads(json.dumps(driver._with_warnings({"status": "checkpoint"}, str(tmp_path))))[
        "warnings"] == [carried]
    _readiness_artifact(tmp_path, [{"name": "docker", "ok": True, "detail": "ok"}])
    status = {"status": "checkpoint", "message": "m"}
    assert driver._with_warnings(status, str(tmp_path)) is status        # none: the status is unchanged
    assert driver._with_warnings(status, str(tmp_path / "no-run")) is status
    _readiness_artifact(tmp_path, [{"name": "n%d" % n, "ok": None, "detail": "x" * 5000, "level": "warn"}
                                   for n in range(20)])
    bounded = readiness.warnings(str(tmp_path))
    assert len(bounded) == 8 and all(len(line) == 600 for line in bounded)


def test_the_refresh_command_names_no_dependency_check_version():
    """#3802 seat review: the README spelled `dc-10.0.3`, which goes stale the day the
    pin moves. The command reads the version from the Dockerfile instead."""
    import re
    readme = (ROOT / "README.md").read_text()
    command = readme[readme.index("docker build --build-arg ASSET_REFRESH="):]
    command = command[:command.index("```")]
    assert not re.search(r"dc-[0-9]", command)
    expression = "sed -n 's/^ARG DEPENDENCY_CHECK_VERSION=//p' Dockerfile"
    assert 'panopticon-tools-nvd:dc-$(%s)"' % expression in command
    versions = [line[len("ARG DEPENDENCY_CHECK_VERSION="):] for line in
                (ROOT / "Dockerfile").read_text().splitlines()
                if line.startswith("ARG DEPENDENCY_CHECK_VERSION=")]
    assert len(versions) == 1 and re.fullmatch(r"[0-9]+(\.[0-9]+)+", versions[0])   # what the sed prints
    assert not re.search(r"dc-[0-9]", (ROOT / "DEVELOPMENT.md").read_text().split(
        "### How old the image's advisory data is")[1].split("### Stable tools-image pins")[0])


def test_the_host_is_told_to_show_the_warnings_before_it_dispatches():
    skill = " ".join((ROOT / "skill" / "SKILL.md").read_text().split())
    guide = " ".join((ROOT / "skill" / "docs" / "guide" / "driver-run-loop.md").read_text().split())
    for text in (skill, guide):
        assert "`warnings`" in text
        assert "before you dispatch" in text or "before it dispatches" in text
    assert "advisory data" in guide.lower() and "7 days" in guide
