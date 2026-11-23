"""#3771: suppression by path name applies to a plain in-tree path and to nothing else.

A scanner result's `uri` is text the target can shape. A location that only SPELLS a
fixture, vendored, virtualenv, run-artifact or bytecode path (URI syntax, dot segments,
escapes) names a file that is not there, and its finding stays in the report."""
import contextlib
import io
import json
import os

import pytest

import scripts.ingest_tools as it
import scripts.synthesize as synthesize
from tests._test_helpers import semgrep_size_stamped

#: A directory each name rule suppresses, and the segment it is disclosed under.
RULES = {
    "fixtures": ("tests/fixtures", it.FIXTURE_SEGMENT),
    "testdata": ("pkg/testdata", it.FIXTURE_SEGMENT),
    "vendor": ("vendor", "vendor"),
    "node_modules": ("web/node_modules", "node_modules"),
    "venv-name": ("tools/.venv", ".venv"),
    "site-packages": ("lib/site-packages", "site-packages"),
    "run-artifact": (".panopticon", it.RUN_ARTIFACT_SEGMENT),
    "git-dir": (".git", it.RUN_ARTIFACT_SEGMENT),
    "bytecode-dir": ("app/__pycache__", it.GENERATED_BYTECODE_SEGMENT),
}


def _spelled(directory):
    """Locations that mention `directory` and do not name a file in it."""
    up = "/".join([".."] * len(directory.split("/")))
    return {
        "dot-segments": "%s/%s/Cargo.lock" % (directory, up),
        "percent-escaped-dots": "%s/%s/Cargo.lock" % (directory, up.replace("..", "%2e%2e")),
        "percent-escaped-slash": "%s/x%%2f..%%2f..%%2fCargo.lock" % directory,
        "backslash": "%s/..\\Cargo.lock" % directory,
        "fragment-after": "%s/x#/../Cargo.lock" % directory,
        "query-after": "%s/x?/../Cargo.lock" % directory,
        "scheme": "https://example.invalid/%s/Cargo.lock" % directory,
        "file-scheme-twice": "file://file://%s/Cargo.lock" % directory,
        "drive": "C:/%s/Cargo.lock" % directory,
        "tab": "%s/Cargo\t.lock" % directory,
    }


def _sarif(*uris, level="error"):
    return {"runs": [semgrep_size_stamped({
        "tool": {"driver": {"name": "semgrep", "rules": []}},
        "results": [{"ruleId": "R%d" % index, "level": level, "message": {"text": "m"},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": uri}, "region": {"startLine": 1}}}]}
                    for index, uri in enumerate(uris)]})]}


def _ingest(tmp_path, *uris, **kwargs):
    tools = tmp_path / "tools"
    tools.mkdir(exist_ok=True)
    (tools / "semgrep.sarif").write_text(json.dumps(_sarif(*uris)), encoding="utf-8")
    suppressed, excluded = [], []
    with contextlib.redirect_stderr(io.StringIO()) as err:
        kept, _dispositions = it.ingest_dir_detailed(
            str(tools), "g1", suppressed_out=suppressed, excluded_out=excluded, **kwargs)
    return kept, suppressed, excluded, err.getvalue()


CASES = [pytest.param(directory, uri, id="%s-%s" % (rule, spelling))
         for rule, (directory, _segment) in RULES.items()
         for spelling, uri in _spelled(directory).items()]


@pytest.mark.parametrize("directory, uri", CASES)
def test_a_location_that_only_spells_a_suppressed_directory_is_kept(tmp_path, directory, uri):
    kept, suppressed, excluded, _err = _ingest(tmp_path, uri)
    assert (len(kept), suppressed, excluded) == (1, [], []), uri
    assert kept[0]["severity"] == "HIGH"


@pytest.mark.parametrize("uri", [
    "#/tests/fixtures/Cargo.lock",                      # the three the issue names
    "tests/fixtures/../../Cargo.lock",
    "tests/fixtures/%2e%2e/%2e%2e/Cargo.lock",
    "tests/fixtures/%2E%2E/%2E%2E/Cargo.lock",
    "?/tests/fixtures/Cargo.lock",
    "#/vendor/lib.js", "#/x/.venv/lib.py", "#/x/__pycache__/a.py",
    "src/app.py#.pyc", "src/app.py?v=.pyc", "src/..%2fapp.pyo",
    ".panopticon/../src/app.py", ".git/../src/app.py", ".worktrees/..\\src\\app.py",
])
def test_the_spellings_the_issue_names_are_kept(tmp_path, uri):
    kept, suppressed, excluded, _err = _ingest(tmp_path, uri)
    assert (len(kept), suppressed, excluded) == (1, [], []), uri


@pytest.mark.parametrize("rule", sorted(RULES))
def test_a_plain_path_under_the_directory_is_still_suppressed(tmp_path, rule):
    directory, segment = RULES[rule]
    for uri in ("%s/pkg/Cargo.lock" % directory, "./%s/Cargo.lock" % directory,
                "/%s/Cargo.lock" % directory, "%s/@scope/pkg+1.2/a b~1.js" % directory,
                "%s/sub.dir/caf\u00e9:1.js" % directory, "%s//a.js" % directory,
                "%s/pkg/a:b.js" % directory, "%s/http://x/a.js" % directory,
                "%s/.../a.js" % directory, "%s/..a/b..js" % directory):
        if rule in ("run-artifact", "git-dir") and uri.startswith("./"):
            continue                      # that rule reads the FIRST segment only
        kept, suppressed, excluded, _err = _ingest(tmp_path, uri)
        assert (kept, [row["suppressed"] for row in suppressed], excluded) == (
            [], [segment], []), uri


def test_bytecode_is_still_suppressed_by_its_suffix(tmp_path):
    kept, suppressed, _excluded, _err = _ingest(tmp_path, "src/app.pyc", "src/app.pyo")
    assert kept == []
    assert [row["suppressed"] for row in suppressed] == [it.GENERATED_BYTECODE_SEGMENT] * 2


def test_include_fixtures_still_keeps_a_plain_fixture_path(tmp_path):
    kept, suppressed, _excluded, _err = _ingest(
        tmp_path, "tests/fixtures/app.js", include_fixtures=True)
    assert (len(kept), suppressed) == (1, [])


@pytest.mark.parametrize("uri", [
    "ops/../src/app.py", "ops/%2e%2e/src/app.py", "#/ops/deploy.py", "ops/x#/../y.py",
    "ops/..\\src\\app.py", "https://example.invalid/ops/deploy.py",
])
def test_an_operators_glob_does_not_exclude_a_location_that_only_spells_its_path(tmp_path, uri):
    """`exclude_paths:` is the operator's, and it names paths in the tree. A location
    that is not one cannot be what they excluded."""
    kept, suppressed, excluded, err = _ingest(tmp_path, uri, exclude_globs=["ops/", "ops/*"])
    assert (len(kept), suppressed, excluded) == (1, [], []), uri
    assert "excluded" not in err


def test_an_operators_glob_still_excludes_a_plain_path(tmp_path):
    kept, suppressed, excluded, err = _ingest(
        tmp_path, "ops/deploy.py", "ops/sub dir/a+b.py", exclude_globs=["ops/"])
    assert (kept, suppressed) == ([], [])
    assert [row["excluded"] for row in excluded] == ["ops/", "ops/"]
    assert "excluded 2 finding" in err


def _venv(root, rel):
    """A virtualenv as a creator leaves one: the marker and an interpreter."""
    home = root / rel
    (home / "bin").mkdir(parents=True)
    (home / "pyvenv.cfg").write_text("home = /usr/bin\nversion = 3.12.0\n", encoding="utf-8")
    (home / "bin" / "python").write_text("", encoding="utf-8")


@pytest.mark.parametrize("uri", [
    "app/env/%2e%2e/patched_auth.py", "app/env/x#/../../patched_auth.py",
    "app/env/lib/a.py?x", "app/env/..\\patched_auth.py", "C:/app/env/lib/a.py",
])
def test_a_marker_confirmed_virtualenv_does_not_suppress_a_spelled_location(tmp_path, uri):
    root = tmp_path / "target"
    _venv(root, "app/env")
    kept, suppressed, _excluded, _err = _ingest(tmp_path, uri, target_root=str(root))
    assert (len(kept), suppressed) == (1, []), uri
    plain, hidden, _excluded, _err = _ingest(tmp_path, "app/env/lib/a.py", target_root=str(root))
    assert (plain, [row["suppressed"] for row in hidden]) == ([], ["pyvenv.cfg:app/env"])


@pytest.mark.parametrize("path", [
    "vendor/a\x07b.js", "vendor/a\x00b.js", "vendor/a\x1fb.js", "vendor/a\x7fb.js",
    "vendor/a\x85b.js", "vendor/a\nb.js", "tests/fixtures/a\rb.js",
])
def test_a_control_character_in_a_location_is_not_a_plain_path(path):
    """Ingest escapes these on the way in; a caller that hands the filter a raw one
    gets the same answer."""
    suppressed_out = []
    kept, excluded, suppressed = it._filter_parsed_findings(
        [{"location": {"file": path}}], False, ["vendor/"], None, None, suppressed_out)
    assert (len(kept), excluded, suppressed, suppressed_out) == (1, 0, {}, [])


@pytest.mark.parametrize("path", [
    "/https://example.invalid/vendor/a.js", "//C:/vendor/a.js", "///file:vendor/a.js",
])
def test_a_scheme_behind_leading_slashes_is_still_a_scheme(path):
    """The name rules strip leading slashes before they read a path, so this does too."""
    suppressed_out = []
    kept, excluded, suppressed = it._filter_parsed_findings(
        [{"location": {"file": path}}], False, ["vendor/"], None, None, suppressed_out)
    assert (len(kept), excluded, suppressed, suppressed_out) == (1, 0, {}, [])


def test_a_finding_with_no_location_is_judged_as_before():
    """An empty location is plain: an operator's `*` still excludes it, as it did."""
    kept, excluded, suppressed = it._filter_parsed_findings(
        [{"location": {"file": ""}}, {"location": {}}, {}], False, ["*"], None, None, [], [])
    assert (kept, excluded, suppressed) == ([], 3, {})
    kept, excluded, suppressed = it._filter_parsed_findings(
        [{"location": {"file": ""}}], False, None, None, None, [], [])
    assert (len(kept), excluded, suppressed) == (1, 0, {})


def test_every_finding_still_lands_in_exactly_one_place():
    parsed = [{"location": {"file": path}} for path in (
        "app/models/order.rb", "app/vendor/j.js", "app/vendor/../models/order.rb",
        "#/tests/fixtures/app.js", "tests/fixtures/app.js", "ops/deploy.py",
        "ops/%2e%2e/app.py", "")]
    suppressed_out, excluded_out = [], []
    kept, excluded, suppressed = it._filter_parsed_findings(
        parsed, False, ["ops/*"], None, None, suppressed_out, excluded_out)
    assert [row["location"]["file"] for row in kept] == [
        "app/models/order.rb", "app/vendor/../models/order.rb", "#/tests/fixtures/app.js",
        "ops/%2e%2e/app.py", ""]
    assert (excluded, suppressed) == (1, {"vendor": 1, it.FIXTURE_SEGMENT: 1})
    assert len(kept) + excluded + sum(suppressed.values()) == len(parsed)


# ---- through to the report ---------------------------------------------------------

def _report(tmp_path, monkeypatch, *uris):
    monkeypatch.chdir(tmp_path)
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "semgrep.sarif").write_text(json.dumps(_sarif(*uris)), encoding="utf-8")
    out = tmp_path / "report.json"
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        synthesize.main(["--repo", "--target", "src", "--tools-dir", str(tools),
                         "--out", str(out)])
    return json.loads(out.read_text(encoding="utf-8"))


@pytest.mark.parametrize("uri", [
    "#/tests/fixtures/Cargo.lock",
    "tests/fixtures/../../Cargo.lock",
    "tests/fixtures/%2e%2e/%2e%2e/Cargo.lock",
    "vendor/../src/app.py",
    "tools/.venv/..\\app.py",
    "src/app.py#.pyc",
])
def test_a_finding_at_a_spelled_location_reaches_the_report(tmp_path, monkeypatch, uri):
    """Ingest keeps it HIGH (above); the report grades a tool finding no advisor has
    verified by its own rule, and that is not this test's."""
    report = _report(tmp_path, monkeypatch, uri)
    assert [row["source"] for row in report["findings"]] == ["tool:semgrep"]
    assert report["findings"][0]["location"]["file"].endswith(uri[-6:])
    assert report["meta"]["coverage"]["tools_suppressed"] == {}


def test_a_finding_at_a_plain_fixture_path_is_suppressed_and_counted(tmp_path, monkeypatch):
    report = _report(tmp_path, monkeypatch, "tests/fixtures/Cargo.lock", "vendor/lib.js")
    assert report["findings"] == []
    assert report["meta"]["coverage"]["tools_suppressed"] == {it.FIXTURE_SEGMENT: 1, "vendor": 1}
