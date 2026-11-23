"""#3749: a requirement with no pinned version is not version 0.0.0.

osv-scanner reports a requirements-file entry that has no `==` pin as version `0.0.0`,
and every advisory whose range starts at zero then matches. In the 5.4 batch that was
135 rows: 120 rejected by the advisor and 15 left in reports as findings. An advisory
matched against a version nobody has is not a claim about the code: such a row is not
a finding, and the report says so as coverage."""
import contextlib
import contextvars
import io
import json

import pytest

import scripts.ingest_tools as it
import scripts.synthesize as synthesize
import scripts.synth.validate_schema as validate_schema
from tests._test_helpers import adopt_panopticon


FIXED = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]
NO_FIX = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
ABSENT = object()


def _affected(name, ecosystem, ranges):
    return {"package": {"name": name, "ecosystem": ecosystem}, "ranges": ranges}


def _package(name, version, *advisories, severity="HIGH", ecosystem="PyPI", ranges=FIXED,
             affected=ABSENT):
    """One package of an osv-scanner capture. Each advisory says which versions of the
    package it covers; by default a range that ends (`introduced 0`, `fixed 2.0`)."""
    said = [_affected(name, ecosystem, ranges)] if affected is ABSENT else affected
    vulnerabilities = []
    for advisory in advisories:
        vulnerability = {"id": advisory, "summary": "affected package",
                         "database_specific": {"severity": severity}}
        if said is not None:
            vulnerability["affected"] = said
        vulnerabilities.append(vulnerability)
    return {"package": {"name": name, "version": version, "ecosystem": ecosystem},
            "vulnerabilities": vulnerabilities, "groups": []}


def _osv(path, *packages):
    return {"results": [{"source": {"path": "/src/" + path}, "packages": list(packages)}]}


def _tree(tmp_path, files):
    root = tmp_path / "root"
    for path, text in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text, encoding="utf-8")
    (root / ".panopticon" / "tools").mkdir(parents=True, exist_ok=True)
    return root


def _ingest(root, captures, with_tree=True):
    # With no tree: a bare directory of captures, as the CI gate has. (A tools directory
    # under `.panopticon/` names its own tree.)
    tools = root / ".panopticon" / "tools" if with_tree else root.parent / "captures"
    tools.mkdir(parents=True, exist_ok=True)
    for name, document in captures.items():
        (tools / name).write_text(json.dumps(document), encoding="utf-8")
    with contextlib.redirect_stderr(io.StringIO()):
        found, dispositions = contextvars.Context().run(
            it.ingest_dir_detailed, str(tools), "g1",
            target_root=str(root) if with_tree else None)
    return found, dispositions


def _kept(found):
    return sorted((finding["tool_evidence"]["package_name"],
                   finding["tool_evidence"]["vulnerable_versions"]) for finding in found)


def _unpinned(dispositions, tool="osv-scanner"):
    return dispositions[tool].get("unpinned")


# ---- at ingest ----------------------------------------------------------------------

def test_an_unpinned_requirements_advisories_are_not_findings(tmp_path):
    root = _tree(tmp_path, {"requirements.txt": "requests>=2.0\nflask==2.0.0\n"})
    found, dispositions = _ingest(root, {"osv-scanner.json": _osv(
        "requirements.txt",
        _package("requests", "0.0.0", "GHSA-aaaa-0001", "GHSA-aaaa-0002"),
        _package("flask", "2.0.0", "GHSA-bbbb-0001"))})
    assert _kept(found) == [("flask", "2.0.0")]
    assert _unpinned(dispositions) == [{
        "manifest": "requirements.txt", "packages": ["requests"], "packages_more": 0,
        "advisories": 2, "ids": ["GHSA-aaaa-0001", "GHSA-aaaa-0002"], "ids_more": 0}]
    assert dispositions["osv-scanner"]["status"] == "ok"
    assert dispositions["osv-scanner"]["findings"] == 3       # what the scanner said, as before


@pytest.mark.parametrize("line", [
    "requests==0.0.0", "requests===0.0.0", "requests == 0.0.0", "Requests==0.0.0",
    "requests[security]==0.0.0", 'requests==0.0.0 ; python_version > "3"',
    "requests==0.0.0 --hash=sha256:abc", "requests==0.0.0  # the first release",
    "requests==0.0.0 \\\n    --hash=sha256:abc",
])
def test_a_requirement_really_pinned_at_that_version_is_kept(tmp_path, line):
    root = _tree(tmp_path, {"requirements.txt": "flask==2.0.0\n%s\n" % line})
    found, dispositions = _ingest(root, {"osv-scanner.json": _osv(
        "requirements.txt", _package("requests", "0.0.0", "GHSA-aaaa-0001"))})
    assert _kept(found) == [("requests", "0.0.0")]
    assert _unpinned(dispositions) is None


@pytest.mark.parametrize("pinned, reported", [
    ("My_Pkg.Name", "my-pkg-name"), ("my-pkg-name", "My_Pkg.Name"), ("a__b", "A-B"),
])
def test_a_name_is_compared_as_pypi_compares_names(tmp_path, pinned, reported):
    root = _tree(tmp_path, {"requirements.txt": "%s==0.0.0\n" % pinned})
    found, _dispositions = _ingest(root, {"osv-scanner.json": _osv(
        "requirements.txt", _package(reported, "0.0.0", "GHSA-aaaa-0001"))})
    assert _kept(found) == [(reported, "0.0.0")]


def test_the_pins_of_a_manifest_are_said_or_said_to_be_unknown(tmp_path):
    import scripts.tools.pip_audit as pip_audit
    root = _tree(tmp_path, {
        "requirements.txt": "-r base.txt\nFlask==2.0.0\nrequests>=1\nx===1.0\ny==1.0,<2\n",
        "base.txt": "my_pkg==0.0.0  # pinned\n", "broken.txt": "-r missing.txt\nz==1\n"})
    assert pip_audit.requirement_pins(str(root / "requirements.txt"), str(root)) == {
        ("flask", "2.0.0"), ("x", "1.0"), ("my-pkg", "0.0.0")}
    assert pip_audit.requirement_pins(str(root / "base.txt"), str(root)) == {("my-pkg", "0.0.0")}
    for unknown in ("broken.txt", "absent.txt"):
        assert pip_audit.requirement_pins(str(root / unknown), str(root)) is None


def test_only_osv_scanners_row_is_judged(tmp_path):
    """The same row from any other scanner is that scanner's own claim."""
    root = _tree(tmp_path, {"requirements.txt": "requests\n"})

    def row(source):
        return {"source": source, "location": {"file": "requirements.txt"},
                "tool_evidence": {"package_name": "requests", "vulnerable_versions": "0.0.0",
                                  "ecosystem": "PyPI", "rule_id": "GHSA-1", "ranges_end": True}}

    kept, rows = it._without_unpinned([row("tool:osv-scanner"), row("tool:trivy"),
                                       row("tool:pip-audit"), row("agent")], str(root))
    assert [finding["source"] for finding in kept] == ["tool:trivy", "tool:pip-audit", "agent"]
    assert [entry["advisories"] for entry in rows] == [1]


@pytest.mark.parametrize("line", [
    "requests", "requests>=0.0.0", "requests~=0.0.0", "requests!=0.0.0", "requests<=0.0.0",
    "requests>0.0.0", "requests==0.0.0.1", "requests==0.0", "requests==0.0.0rc1",
    "requests==0.0.*", "requests>=0.0.0,<1", "requests==0.0.0,<1",
    "requests @ https://example.invalid/requests-0.0.0.tar.gz",
    'requests ; python_version > "3"', "# requests==0.0.0", "other==0.0.0",
    "requests2==0.0.0", "xrequests==0.0.0", "-e .", "",
])
def test_anything_short_of_an_exact_pin_is_unpinned(tmp_path, line):
    root = _tree(tmp_path, {"requirements.txt": "flask==2.0.0\n%s\n" % line})
    found, dispositions = _ingest(root, {"osv-scanner.json": _osv(
        "requirements.txt", _package("requests", "0.0.0", "GHSA-aaaa-0001"))})
    assert found == []
    assert [row["packages"] for row in _unpinned(dispositions)] == [["requests"]]


def test_a_pin_in_an_included_file_counts(tmp_path):
    root = _tree(tmp_path, {"requirements.txt": "-r base.txt\nflask\n",
                            "base.txt": "requests==0.0.0\n"})
    found, dispositions = _ingest(root, {"osv-scanner.json": _osv(
        "requirements.txt", _package("requests", "0.0.0", "GHSA-aaaa-0001"),
        _package("flask", "0.0.0", "GHSA-bbbb-0001"))})
    assert _kept(found) == [("requests", "0.0.0")]
    assert [row["packages"] for row in _unpinned(dispositions)] == [["flask"]]


@pytest.mark.parametrize("files, with_tree, why", [
    ({"requirements.txt": "requests==0.0.0\n"}, False, "no tree to read"),
    ({}, True, "the manifest is not there"),
    ({"requirements.txt": "-r missing.txt\nrequests==0.0.0\n"}, True, "an include that is not there"),
    ({"requirements.txt": "requests==0.0.0\n" + "x" * (2 * 1024 * 1024)}, True, "too large to read whole"),
])
def test_a_version_that_cannot_be_checked_is_unknown(tmp_path, files, with_tree, why):
    """A real `==0.0.0` pin is rare. An unknown version treated as known is the fault."""
    root = _tree(tmp_path, files)
    found, dispositions = _ingest(root, {"osv-scanner.json": _osv(
        "requirements.txt", _package("requests", "0.0.0", "GHSA-aaaa-0001"))}, with_tree)
    assert found == [], why
    assert _unpinned(dispositions)[0]["advisories"] == 1


@pytest.mark.parametrize("captures, kept", [
    ({"osv-scanner.json": _osv("package-lock.json", _package("left-pad", "0.0.0", "GHSA-1", ecosystem="npm"))},
     [("left-pad", "0.0.0")]),
    ({"osv-scanner.json": _osv("poetry.lock", _package("requests", "0.0.0", "GHSA-1"))},
     [("requests", "0.0.0")]),
    ({"osv-scanner.json": _osv("Pipfile.lock", _package("requests", "0.0.0", "GHSA-1"))},
     [("requests", "0.0.0")]),
    ({"osv-scanner.json": _osv("requirements.txt", _package("requests", "1.0.0", "GHSA-1"))},
     [("requests", "1.0.0")]),
    ({"osv-scanner.json": _osv("requirements.txt", _package("requests", "0.0.00", "GHSA-1"))},
     [("requests", "0.0.00")]),
    ({"osv-scanner.json": _osv("requirements.txt", _package("left-pad", "0.0.0", "GHSA-1", ecosystem="npm"))},
     [("left-pad", "0.0.0")]),
], ids=["an npm lockfile", "poetry.lock", "Pipfile.lock", "another version", "almost the placeholder",
        "another ecosystem in a .txt"])
def test_everything_else_is_untouched(tmp_path, captures, kept):
    root = _tree(tmp_path, {"requirements.txt": "requests\n"})
    found, dispositions = _ingest(root, captures)
    assert _kept(found) == kept
    assert _unpinned(dispositions) is None


def test_another_scanners_row_at_that_version_is_untouched(tmp_path):
    root = _tree(tmp_path, {"requirements.txt": "requests\n"})
    found, dispositions = _ingest(root, {"pip-audit.json": {"fixes": [], "dependencies": [{
        "name": "requests", "version": "0.0.0", "vulns": [
            {"id": "PYSEC-1", "severity": "HIGH", "description": "x", "fix_versions": ["1"],
             "aliases": []}]}]}})
    assert [finding["source"] for finding in found] == ["tool:pip-audit"]
    assert _unpinned(dispositions, "pip-audit") is None


def test_each_manifest_has_its_own_row_bounded_with_what_was_left_out_counted(tmp_path):
    names = ["pkg%02d" % n for n in range(25)]
    root = _tree(tmp_path, {"requirements.txt": "\n".join(names) + "\n",
                            "svc/requirements.txt": "requests\n"})
    document = {"results": [
        {"source": {"path": "/src/requirements.txt"},
         "packages": [_package(name, "0.0.0", "GHSA-%s-1" % name, "GHSA-%s-2" % name)
                      for name in reversed(names)]},
        {"source": {"path": "/src/svc/requirements.txt"},
         "packages": [_package("requests", "0.0.0", "GHSA-r-1")]}]}
    found, dispositions = _ingest(root, {"osv-scanner.json": document})
    assert found == []
    first, second = _unpinned(dispositions)
    assert (first["manifest"], first["advisories"]) == ("requirements.txt", 50)
    assert first["packages"] == names[:20] and first["packages_more"] == 5
    assert first["ids"] == sorted("GHSA-%s-%d" % (name, n) for name in names for n in (1, 2))[:20]
    assert first["ids_more"] == 30
    assert second == {"manifest": "svc/requirements.txt", "packages": ["requests"],
                      "packages_more": 0, "advisories": 1, "ids": ["GHSA-r-1"], "ids_more": 0}


def test_what_the_scanner_named_is_made_inert_and_bounded(tmp_path):
    hostile = "evil\x1b[2J" + "x" * 500
    root = _tree(tmp_path, {"requirements.txt": "requests\n"})
    found, dispositions = _ingest(root, {"osv-scanner.json": _osv(
        "requirements.txt", _package(hostile, "0.0.0", "GHSA-\x1b[2J" + "y" * 500))})
    assert found == []
    row = _unpinned(dispositions)[0]
    for text in row["packages"] + row["ids"]:
        assert "\x1b" not in text and len(text) <= 201      # 200 and the mark of the cut


def test_an_operators_exclusion_still_comes_first(tmp_path):
    """A manifest the operator scoped out is counted as their exclusion, as before, and
    not disclosed here as well."""
    root = _tree(tmp_path, {"ops/requirements.txt": "requests\n"})
    (root / ".panopticon" / "tools" / "osv-scanner.json").write_text(json.dumps(_osv(
        "ops/requirements.txt", _package("requests", "0.0.0", "GHSA-aaaa-0001"))), encoding="utf-8")
    excluded = []
    with contextlib.redirect_stderr(io.StringIO()):
        found, dispositions = it.ingest_dir_detailed(
            str(root / ".panopticon" / "tools"), "g1", target_root=str(root),
            exclude_globs=["ops/"], excluded_out=excluded)
    assert found == [] and len(excluded) == 1
    assert _unpinned(dispositions) is None


# ---- through to the report ------------------------------------------------------------

def _report(tmp_path, monkeypatch, files, document, extra=(), verdict="CONFIRMED"):
    tmp_path.mkdir(exist_ok=True)
    monkeypatch.chdir(tmp_path)
    adopt_panopticon(str(tmp_path))
    for path, text in files.items():
        (tmp_path / path).write_text(text, encoding="utf-8")
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "osv-scanner.json").write_text(json.dumps(document), encoding="utf-8")
    agent = tmp_path / "findings-g1-SEC.json"
    agent.write_text(json.dumps({"findings": []}), encoding="utf-8")
    common = ["--repo", "--target", "src", "--root", str(tmp_path), "--tools-dir", str(tools),
              "--fail-on", "high", *extra]
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        contextvars.Context().run(synthesize.main, common + [
            "--emit-verify-queue", "--out", str(tmp_path / "unused.json"), str(agent)])
    queue_file = tmp_path / ".panopticon" / "verify-queue.json"
    queue = json.loads(queue_file.read_text(encoding="utf-8")) if queue_file.exists() else {
        "entries": [], "run_id": None}
    verdicts = tmp_path / "verdicts"
    verdicts.mkdir()
    for entry in queue["entries"]:
        (verdicts / ("%s.json" % entry["queue_id"])).write_text(json.dumps({
            "run_id": queue["run_id"], "finding_id": entry["finding"].get("id"),
            "verdict": verdict, "reasoning": "the advisor's own words"}), encoding="utf-8")
    out, said = tmp_path / "report.json", io.StringIO()
    with contextlib.redirect_stdout(said), contextlib.redirect_stderr(io.StringIO()):
        contextvars.Context().run(synthesize.main, common + [
            "--verdicts-dir", str(verdicts), "--out", str(out), str(agent)])
    report = json.loads(out.read_text(encoding="utf-8"))
    return report, queue, said.getvalue(), (tmp_path / "report.json.html").read_text(encoding="utf-8")


def _standing(report):
    summary = report["summary"]
    return (summary["gate"], summary["overall_grade"], summary["provisional_grade"],
            summary["health"], summary["risk_level"], summary["counts"])


FILES = {"requirements.txt": "requests>=2.0\nflask==2.0.0\n"}
PINNED = _package("flask", "2.0.0", "GHSA-bbbb-0001", severity="LOW")
UNPINNED = _package("requests", "0.0.0", "GHSA-aaaa-0001", "GHSA-aaaa-0002")


@pytest.mark.parametrize("extra", [(), ("--gate-unverified",)], ids=["default", "gate-unverified"])
def test_the_rows_reach_no_advisor_and_no_part_of_the_report_but_its_coverage(
        tmp_path, monkeypatch, extra):
    """A run whose only HIGH was such a row reads as the same run without it, whether
    or not unverified scanner findings gate."""
    report, queue, said, page = _report(tmp_path / "with", monkeypatch, FILES,
                                        _osv("requirements.txt", UNPINNED, PINNED), extra)
    plain, _queue, plain_said, plain_page = _report(
        tmp_path / "without", monkeypatch, FILES, _osv("requirements.txt", PINNED), extra)
    everywhere = json.dumps([queue, report["findings"], report["discarded_claims"]])
    assert "GHSA-aaaa" not in everywhere and "0.0.0" not in everywhere
    assert [entry["finding"]["tool_evidence"]["package_name"] for entry in queue["entries"]] == ["flask"]
    assert _standing(report) == _standing(plain)
    assert report["meta"]["coverage"]["tools_unpinned"] == {"osv-scanner": [{
        "manifest": "requirements.txt", "packages": ["requests"], "packages_more": 0,
        "advisories": 2, "ids": ["GHSA-aaaa-0001", "GHSA-aaaa-0002"], "ids_more": 0}]}
    assert plain["meta"]["coverage"]["tools_unpinned"] == {}
    line = ("1 requirement in requirements.txt has no pinned version, so 2 advisories could not "
            "be matched to an installed version (requests: GHSA-aaaa-0001, GHSA-aaaa-0002)")
    assert line in said and line in page
    for quiet in (plain_said, plain_page):
        assert "no pinned version" not in quiet
    assert "==0.0.0" not in said + page and "requests 0.0.0" not in said + page
    assert validate_schema.schema_errors(report) == []


def test_it_does_not_touch_certification(tmp_path, monkeypatch):
    report, _queue, _said, _page = _report(tmp_path / "with", monkeypatch, FILES,
                                           _osv("requirements.txt", UNPINNED, PINNED))
    plain, _queue, _said, _page = _report(tmp_path / "without", monkeypatch, FILES,
                                          _osv("requirements.txt", PINNED))
    for key in ("coverage_certified", "coverage_note", "grade_cap", "grade_shortfalls"):
        assert report["summary"][key] == plain["summary"][key], key


def test_the_line_counts_and_bounds_what_it_names(tmp_path, monkeypatch):
    names = ["pkg%02d" % n for n in range(25)]
    files = {"requirements.txt": "\n".join(names) + "\n"}
    document = _osv("requirements.txt", *[_package(name, "0.0.0", "GHSA-%s-1" % name) for name in names])
    report, _queue, said, page = _report(tmp_path, monkeypatch, files, document)
    assert report["findings"] == []
    line = ("25 requirements in requirements.txt have no pinned version, so 25 advisories could "
            "not be matched to an installed version (")
    assert line in said and line in page
    assert "+5 more" in said and "+5 more" in page


def test_a_report_from_before_this_renders_no_line():
    import scripts.html_report as html_report
    import scripts.synth.render as render
    for block in (None, {}, [], {"osv-scanner": "lots"}, {"osv-scanner": [{"manifest": 7}]},
                  {"osv-scanner": [{"manifest": "r.txt", "packages": "x", "advisories": "many"}]}):
        assert render._unpinned_lines(block) == []
        assert html_report._render_unpinned({"coverage": {"tools_unpinned": block}}) == ""
    assert html_report._render_unpinned({}) == ""


def test_the_page_escapes_what_the_scanner_named(tmp_path, monkeypatch):
    files = {"requirements.txt": "x\n"}
    document = _osv("requirements.txt", _package("<b>bold</b>", "0.0.0", "GHSA-<i>-1"))
    report, _queue, _said, page = _report(tmp_path, monkeypatch, files, document)
    assert report["meta"]["coverage"]["tools_unpinned"]["osv-scanner"][0]["packages"] == ["<b>bold</b>"]
    assert "&lt;b&gt;bold&lt;/b&gt;: GHSA-&lt;i&gt;-1" in page
    assert "<b>bold</b>" not in page and "GHSA-<i>-1" not in page


# ---- seat review of #3790: an advisory with no fix covers every version ----------------

OPEN_AFTER_A_FIX = [{"type": "ECOSYSTEM", "events": [
    {"introduced": "0"}, {"fixed": "1.0"}, {"introduced": "2.0"}]}]


@pytest.mark.parametrize("label, package", [
    ("no fix", _package("pycrypto", "0.0.0", "GHSA-nofix-0001", ranges=NO_FIX)),
    ("a malicious-package record", _package("evilpkg", "0.0.0", "MAL-2026-0001")),
    ("a malicious-package record with no fix", _package("evilpkg", "0.0.0", "MAL-2026-0002", ranges=NO_FIX)),
    ("open again after a fix", _package("p", "0.0.0", "GHSA-open-0001", ranges=OPEN_AFTER_A_FIX)),
    ("two ranges, one open", _package("p", "0.0.0", "GHSA-two-0001", ranges=FIXED + NO_FIX)),
    ("two entries for the package, one open", _package("p", "0.0.0", "GHSA-two-0002", affected=[
        _affected("p", "PyPI", FIXED), _affected("P", "PyPI", NO_FIX)])),
    ("no affected entry at all", _package("p", "0.0.0", "GHSA-none-0001", affected=None)),
    ("an empty affected list", _package("p", "0.0.0", "GHSA-none-0002", affected=[])),
    ("no entry for this package", _package("p", "0.0.0", "GHSA-none-0003", affected=[
        _affected("other", "PyPI", FIXED)])),
    ("the entry is for another ecosystem", _package("p", "0.0.0", "GHSA-none-0004", affected=[
        _affected("p", "npm", FIXED)])),
    ("the ecosystem differs in case", _package("p", "0.0.0", "GHSA-none-0005", affected=[
        _affected("p", "pypi", FIXED)])),
    ("affected is not a list", _package("p", "0.0.0", "GHSA-bad-0001", affected={"p": FIXED})),
    ("an entry is not an object", _package("p", "0.0.0", "GHSA-bad-0002", affected=["p"])),
    ("no ranges", _package("p", "0.0.0", "GHSA-bad-0003", affected=[
        {"package": {"name": "p", "ecosystem": "PyPI"}, "versions": ["1.0", "1.1"]}])),
    ("an empty ranges list", _package("p", "0.0.0", "GHSA-bad-0004", ranges=[])),
    ("ranges is not a list", _package("p", "0.0.0", "GHSA-bad-0005", ranges="0-2.0")),
    ("a range is not an object", _package("p", "0.0.0", "GHSA-bad-0006", ranges=["0-2.0"])),
    ("a range with no events", _package("p", "0.0.0", "GHSA-bad-0007", ranges=[{"type": "ECOSYSTEM"}])),
    ("events is empty", _package("p", "0.0.0", "GHSA-bad-0008", ranges=[{"events": []}])),
    ("an event is not an object", _package("p", "0.0.0", "GHSA-bad-0009",
                                           ranges=[{"events": ["introduced 0", {"fixed": "1"}]}])),
    ("an event of a kind nobody knows", _package("p", "0.0.0", "GHSA-bad-0010",
                                                 ranges=[{"events": [{"introduced": "0"}, {"maybe": "1"}]}])),
    ("the open range is listed first", _package("p", "0.0.0", "GHSA-two-0003", ranges=NO_FIX + FIXED)),
    ("an entry that cannot be read beside one that can", _package("p", "0.0.0", "GHSA-bad-0013", affected=[
        _affected("p", "PyPI", FIXED), "p"])),
    ("an entry with no package beside one that can be read", _package("p", "0.0.0", "GHSA-bad-0014", affected=[
        _affected("p", "PyPI", FIXED), {"ranges": NO_FIX}])),
    ("an entry whose package has no name", _package("p", "0.0.0", "GHSA-bad-0015", affected=[
        _affected("p", "PyPI", FIXED), {"package": {"ecosystem": "PyPI"}, "ranges": NO_FIX}])),
    ("something that is not an event between two that are", _package("p", "0.0.0", "GHSA-bad-0016", ranges=[
        {"events": [{"introduced": "0"}, "junk", {"fixed": "1"}]}])),
    ("an event that says two things", _package("p", "0.0.0", "GHSA-bad-0017", ranges=[
        {"events": [{"introduced": "0"}, {"fixed": "1", "introduced": "2"}]}])),
    ("an unknown kind of event before the fix", _package("p", "0.0.0", "GHSA-bad-0018", ranges=[
        {"events": [{"introduced": "0"}, {"maybe": "1"}, {"fixed": "2"}]}])),
    ("a fix with nothing introduced", _package("p", "0.0.0", "GHSA-bad-0011",
                                               ranges=[{"events": [{"fixed": "1"}]}])),
    ("the fix is listed before the introduction", _package("p", "0.0.0", "GHSA-bad-0012",
                                                           ranges=[{"events": [{"fixed": "1"}, {"introduced": "0"}]}])),
])
def test_an_advisory_that_may_cover_every_version_is_still_a_finding(tmp_path, label, package):
    """The first rule left out every `0.0.0` row. An advisory with no fix is true of
    whatever version gets installed: a malicious package, an unfixed CVE on an abandoned
    one. Left out, the gate passed. Unless every range for THIS package ends, the row
    stays a finding, as on main; so does one whose ranges cannot be read."""
    root = _tree(tmp_path, {"requirements.txt": "p\npycrypto\nevilpkg\n"})
    found, dispositions = _ingest(root, {"osv-scanner.json": _osv("requirements.txt", package)})
    assert [finding["tool_evidence"]["package_name"] for finding in found] == [
        package["package"]["name"]], label
    assert _unpinned(dispositions) is None, label


@pytest.mark.parametrize("label, ranges", [
    ("a fix", FIXED),
    ("a last affected version", [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "1.9"}]}]),
    ("a limit", [{"type": "GIT", "events": [{"introduced": "0"}, {"limit": "abc"}]}]),
    ("two ranges that both end", FIXED + [{"type": "ECOSYSTEM", "events": [{"introduced": "3.0"}, {"fixed": "3.1"}]}]),
    ("fixed, opened again and fixed again", [{"type": "ECOSYSTEM", "events": [
        {"introduced": "0"}, {"fixed": "1.0"}, {"introduced": "2.0"}, {"fixed": "2.1"}]}]),
])
def test_an_advisory_whose_ranges_all_end_is_still_left_out(tmp_path, label, ranges):
    root = _tree(tmp_path, {"requirements.txt": "p\n"})
    found, dispositions = _ingest(root, {"osv-scanner.json": _osv(
        "requirements.txt", _package("p", "0.0.0", "GHSA-ends-0001", ranges=ranges))})
    assert found == [], label
    assert _unpinned(dispositions)[0]["ids"] == ["GHSA-ends-0001"]


def test_a_record_that_another_id_calls_malicious_is_still_a_finding(tmp_path):
    root = _tree(tmp_path, {"requirements.txt": "p\n"})
    package = _package("p", "0.0.0", "GHSA-alias-0001")
    package["vulnerabilities"][0]["aliases"] = ["CVE-2026-0001", "MAL-2026-0003"]
    found, dispositions = _ingest(root, {"osv-scanner.json": _osv("requirements.txt", package)})
    assert len(found) == 1 and _unpinned(dispositions) is None
    # Only that prefix, at the start: an id that merely contains it is not one.
    package["vulnerabilities"][0]["aliases"] = ["CVE-2026-0001", "GHSA-MAL-0003", "mal-1"]
    found, dispositions = _ingest(root, {"osv-scanner.json": _osv("requirements.txt", package)})
    assert found == [] and _unpinned(dispositions)[0]["ids"] == ["GHSA-alias-0001"]


@pytest.mark.parametrize("said", ["true", 1, "yes", [True], {"ends": True}, None, False])
def test_only_the_adapters_own_yes_leaves_a_row_out(tmp_path, said):
    root = _tree(tmp_path, {"requirements.txt": "requests\n"})
    row = {"source": "tool:osv-scanner", "location": {"file": "requirements.txt"},
           "tool_evidence": {"package_name": "requests", "vulnerable_versions": "0.0.0",
                             "ecosystem": "PyPI", "rule_id": "GHSA-1", "ranges_end": said}}
    kept, rows = it._without_unpinned([row], str(root))
    assert (len(kept), rows) == (1, [])
    assert "ranges_end" not in kept[0]["tool_evidence"]


@pytest.mark.parametrize("name", [None, 7, ["requests"], {"n": "requests"}])
def test_a_row_whose_package_name_is_not_text_is_never_judged(tmp_path, name):
    """Whatever the adapter said of its ranges: there is no name to look a pin up by."""
    root = _tree(tmp_path, {"requirements.txt": "requests\n"})
    row = {"source": "tool:osv-scanner", "location": {"file": "requirements.txt"},
           "tool_evidence": {"package_name": name, "vulnerable_versions": "0.0.0",
                             "ecosystem": "PyPI", "rule_id": "GHSA-1", "ranges_end": True}}
    kept, rows = it._without_unpinned([row], str(root))
    assert (len(kept), rows) == (1, [])


def test_the_adapters_note_reaches_no_finding(tmp_path):
    """`ranges_end` is what the adapter read for this rule. It is taken off every
    finding at ingest, kept or not, pinned or in a lockfile."""
    root = _tree(tmp_path, {"requirements.txt": "p==0.0.0\nq==1.0\n", "poetry.lock": ""})
    document = _osv("requirements.txt", _package("p", "0.0.0", "GHSA-ends-0001"),
                    _package("q", "1.0", "GHSA-ends-0002"),
                    _package("r", "0.0.0", "GHSA-nofix-0001", ranges=NO_FIX))
    document["results"] += _osv("poetry.lock", _package("s", "0.0.0", "GHSA-ends-0003"))["results"]
    found, _dispositions = _ingest(root, {"osv-scanner.json": document})
    assert len(found) == 4
    assert all("ranges_end" not in finding["tool_evidence"] for finding in found)
    # The adapter itself says it only when it is so.
    from scripts.tools.osv_scanner import OsvScannerAdapter
    parsed = OsvScannerAdapter().parse(json.dumps(document).encode("utf-8"), "g")
    assert [finding["tool_evidence"].get("ranges_end") for finding in parsed] == [
        True, True, None, True]


def test_another_packages_open_range_in_the_same_record_is_ignored(tmp_path):
    """One advisory often covers several packages. Only this package's ranges count,
    with its name compared as PyPI compares names."""
    root = _tree(tmp_path, {"requirements.txt": "my_pkg\n"})
    package = _package("my_pkg", "0.0.0", "GHSA-shared-0001", affected=[
        _affected("My.Pkg", "PyPI", FIXED), _affected("sibling", "PyPI", NO_FIX),
        _affected("my-pkg", "npm", NO_FIX)])
    found, dispositions = _ingest(root, {"osv-scanner.json": _osv("requirements.txt", package)})
    assert found == []
    assert _unpinned(dispositions)[0]["packages"] == ["my_pkg"]


def test_one_package_can_have_both_kinds_of_advisory(tmp_path):
    root = _tree(tmp_path, {"requirements.txt": "p\n"})
    package = _package("p", "0.0.0", "GHSA-ends-0001")
    package["vulnerabilities"] += _package("p", "0.0.0", "GHSA-nofix-0001", ranges=NO_FIX)["vulnerabilities"]
    found, dispositions = _ingest(root, {"osv-scanner.json": _osv("requirements.txt", package)})
    assert [finding["tool_evidence"]["rule_id"] for finding in found] == ["GHSA-nofix-0001"]
    assert _unpinned(dispositions) == [{
        "manifest": "requirements.txt", "packages": ["p"], "packages_more": 0,
        "advisories": 1, "ids": ["GHSA-ends-0001"], "ids_more": 0}]


def test_the_ci_gate_still_fails_on_an_unpinned_package_with_no_fix(tmp_path):
    """The seat's probe. Two unpinned CRITICAL rows, one with no fix and one malicious
    package: with the first rule the CI gate found nothing and passed, in both modes."""
    import scripts.security_gate as gate
    import scripts.tools_manifest as tools_manifest
    root = _tree(tmp_path, {"requirements.txt": "pycrypto\nevilpkg\nrequests\n"})
    tools = root / ".panopticon" / "tools"
    capture = tools / "osv-scanner.json"
    capture.write_text(json.dumps(_osv(
        "requirements.txt",
        _package("pycrypto", "0.0.0", "GHSA-nofix-0001", severity="CRITICAL", ranges=NO_FIX),
        _package("evilpkg", "0.0.0", "MAL-2026-0001", severity="CRITICAL"),
        _package("requests", "0.0.0", "GHSA-ends-0001", severity="CRITICAL"))), encoding="utf-8")
    manifest = root / ".panopticon" / "tools-manifest.json"
    tools_manifest.write_manifest(str(manifest), ["osv-scanner"], [str(capture)])
    for mode in ("standard", "redteam"):
        with contextlib.redirect_stderr(io.StringIO()):
            _findings, _dispositions, failures, high, _suppressed = contextvars.Context().run(
                gate.evaluate, str(tools), str(manifest), security_mode=mode)
        assert sorted(finding["tool_evidence"]["rule_id"] for finding in high) == [
            "GHSA-nofix-0001", "MAL-2026-0001"], mode
        assert failures == [], mode


def test_the_report_fails_its_gate_on_an_unpinned_package_with_no_fix(tmp_path, monkeypatch):
    files = {"requirements.txt": "pycrypto\nrequests\n"}
    document = _osv("requirements.txt",
                    _package("pycrypto", "0.0.0", "GHSA-nofix-0001", ranges=NO_FIX),
                    _package("requests", "0.0.0", "GHSA-ends-0001"))
    report, queue, said, _page = _report(tmp_path, monkeypatch, files, document)
    assert report["summary"]["gate"] == "FAIL"
    assert [row["tool_evidence"]["rule_id"] for row in report["findings"]] == ["GHSA-nofix-0001"]
    assert [entry["finding"]["tool_evidence"]["rule_id"] for entry in queue["entries"]] == [
        "GHSA-nofix-0001"]
    assert report["meta"]["coverage"]["tools_unpinned"]["osv-scanner"][0]["ids"] == ["GHSA-ends-0001"]
    assert "(requests: GHSA-ends-0001)" in said and "GHSA-nofix-0001)" not in said


# ---- seat review of #3790: the smaller items ---------------------------------------------

@pytest.mark.parametrize("text", [
    "requests==0.0.0 \\\r\n    --hash=sha256:abc\r\n",          # pip-compile on Windows
    "flask==1.0\r\nrequests==0.0.0\r\n",
    "requests==0.0.0 --config-settings=KEY=VALUE\n",
    'requests==0.0.0 --config-settings "KEY=VALUE"\n',
    "requests==0.0.0 --global-option=--no-user-cfg --hash=sha256:abc\n",
    "requests [security]==0.0.0\n", "requests[security] == 0.0.0\n", "requests  ==0.0.0\n",
])
def test_a_real_pin_is_read_in_these_spellings_too(tmp_path, text):
    root = tmp_path / "root"
    (root / ".panopticon" / "tools").mkdir(parents=True)
    (root / "requirements.txt").write_bytes(text.encode("utf-8"))
    found, dispositions = _ingest(root, {"osv-scanner.json": _osv(
        "requirements.txt", _package("requests", "0.0.0", "GHSA-aaaa-0001"))})
    assert _kept(found) == [("requests", "0.0.0")], text
    assert _unpinned(dispositions) is None


@pytest.mark.parametrize("name", [None, 7, ["requests"], {"n": "requests"}, True])
def test_a_package_name_that_is_not_text_does_not_stop_ingest(tmp_path, name):
    root = _tree(tmp_path, {"requirements.txt": "requests\n"})
    found, dispositions = _ingest(root, {"osv-scanner.json": _osv(
        "requirements.txt", _package(name, "0.0.0", "GHSA-aaaa-0001"),
        _package("requests", "0.0.0", "GHSA-bbbb-0001"))})
    assert dispositions["osv-scanner"]["status"] == "ok"
    assert len(found) == 1 and found[0]["tool_evidence"]["rule_id"] == "GHSA-aaaa-0001"
    assert _unpinned(dispositions)[0]["packages"] == ["requests"]


@pytest.mark.parametrize("ecosystem", ["pypi", "PYPI", "PyPI ", "PyPI:3", "Pypi", "", None])
def test_the_ecosystem_is_compared_exactly(tmp_path, ecosystem):
    root = _tree(tmp_path, {"requirements.txt": "requests\n"})
    found, dispositions = _ingest(root, {"osv-scanner.json": _osv(
        "requirements.txt", _package("requests", "0.0.0", "GHSA-aaaa-0001", ecosystem=ecosystem,
                                     affected=[_affected("requests", ecosystem, FIXED)]))})
    assert len(found) == 1
    assert _unpinned(dispositions) is None


def test_advisories_counts_the_rows_left_out_and_ids_lists_each_id_once(tmp_path):
    """Two packages can share one advisory: two rows left out, one id."""
    root = _tree(tmp_path, {"requirements.txt": "a\nb\n"})
    found, dispositions = _ingest(root, {"osv-scanner.json": _osv(
        "requirements.txt", _package("a", "0.0.0", "GHSA-shared-0001", "GHSA-a-0001"),
        _package("b", "0.0.0", "GHSA-shared-0001"))})
    assert found == []
    row = _unpinned(dispositions)[0]
    assert (row["advisories"], row["ids"]) == (3, ["GHSA-a-0001", "GHSA-shared-0001"])
