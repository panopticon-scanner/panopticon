"""#3755: a scanner finding in a test path or a dev-only manifest.

Whether a path is a test path is a fact, and each advisor decided it again: the same
finding was confirmed in one run and rejected as "test scaffolding" in the next, and
that verdict decided the gate. The controller now states the fact at ingest
(`tool_evidence.path_context`), and one rule says what such a finding does to the gate:
in `--security standard` it is reported and not counted; in `--security redteam` it
counts only when CRITICAL or secret-class (#1578's rule, `gates_when_suppressed`)."""
import contextlib
import contextvars
import io
import json

import pytest

import scripts.evidence as evidence
import scripts.ingest_tools as it
import scripts.synthesize as synthesize
from tests._test_helpers import adopt_panopticon, semgrep_size_stamped

TEST_DIRS = ("test", "tests", "spec", "__tests__", "e2e", "testdata", "fixtures", "__fixtures__")


def _sarif(tool, *uris, rule="R1", level="error"):
    run = {"tool": {"driver": {"name": tool, "rules": []}},
           "results": [{"ruleId": rule, **({"level": level} if level else {}),
                        "message": {"text": "m"},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": uri}, "region": {"startLine": 1}}}]}
                       for uri in uris]}
    return {"runs": [semgrep_size_stamped(run) if tool == "semgrep" else run]}


def _osv(path, name="left-pad", version="1.0.0", severity="CRITICAL", advisory="GHSA-aaaa-bbbb-cccc"):
    return {"results": [{"source": {"path": "/src/" + path}, "packages": [{
        "package": {"name": name, "version": version, "ecosystem": "npm"},
        "vulnerabilities": [{"id": advisory, "summary": "affected package",
                             "database_specific": {"severity": severity}}],
        "groups": []}]}]}


def _pip_audit(severity="CRITICAL"):
    return {"fixes": [], "dependencies": [{"name": "left-pad", "version": "1.0.0", "vulns": [
        {"id": "PYSEC-2026-1", "severity": severity, "description": "RCE",
         "fix_versions": ["2.0"], "aliases": []}]}]}


def _ingest(tmp_path, captures, **kwargs):
    tools = tmp_path / "tools"
    tools.mkdir(parents=True, exist_ok=True)
    for name, document in captures.items():
        (tools / name).write_text(json.dumps(document), encoding="utf-8")
    with contextlib.redirect_stderr(io.StringIO()):
        kept, _dispositions = _fresh(it.ingest_dir_detailed, str(tools), "g1", **kwargs)
    return kept


def _fresh(call, *args, **kwargs):
    """`call` in a context of its own, as the host's parse is in a process of its own.
    `tools/pip_audit.py` keeps the manifest an `invoke` chose in a context variable, so
    a pip-audit capture parsed after another test's `invoke` is labelled with THAT
    test's file (CI's shard order did exactly this to the first push of this file)."""
    return contextvars.Context().run(call, *args, **kwargs)


def _contexts(findings):
    return {finding["location"]["file"]: (finding.get("tool_evidence") or {}).get("path_context")
            for finding in findings}


# ---- the fact, at ingest ------------------------------------------------------------

def test_the_list_of_test_directories_is_the_one_ruled():
    assert it.TEST_DIRS == frozenset(TEST_DIRS)


@pytest.mark.parametrize("directory", TEST_DIRS)
def test_a_finding_under_a_test_directory_is_marked(tmp_path, directory):
    paths = ["%s/keys/id_rsa" % directory, "pkg/%s/a.py" % directory,
             "a/b/%s/c/d/e.js" % directory]
    found = _ingest(tmp_path, {"semgrep.sarif": _sarif("semgrep", *paths)}, include_fixtures=True)
    assert _contexts(found) == {path: "test" for path in paths}


@pytest.mark.parametrize("path", [
    "src/app.py",
    "testing/helpers.py", "specs/openapi.yaml",        # dropped from the list on purpose
    "src/test_app.py", "pkg/foo_test.go", "app.spec.ts",   # named like a test, not in a test directory
    "Tests/a.py", "TEST/a.py", "Spec/a.rb",            # the match is exact and case-sensitive
    "attest/a.py", "tests2/a.py", "mytests/a.py", "latest/a.py",
    "tests",                                           # a FILE named like one
    "src/tests.py",
])
def test_a_finding_anywhere_else_is_not_marked(tmp_path, path):
    found = _ingest(tmp_path, {"semgrep.sarif": _sarif("semgrep", path)})
    assert _contexts(found) == {path: None}


@pytest.mark.parametrize("path", [
    "tests/../src/app.py", "#/tests/app.py", "tests/%2e%2e/src/app.py", "tests\\app.py",
])
def test_a_location_that_is_not_a_plain_path_is_never_marked(tmp_path, path):
    """#3771: such a location names no file in the tree, whatever it spells."""
    found = _ingest(tmp_path, {"semgrep.sarif": _sarif("semgrep", path)})
    assert [(finding.get("tool_evidence") or {}).get("path_context") for finding in found] == [None]


def _tree(tmp_path, files):
    """A review root holding `files` ({path: text}), and its tools directory."""
    root = tmp_path / "root"
    for path, text in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text, encoding="utf-8")
    (root / ".panopticon").mkdir(parents=True, exist_ok=True)
    return root


def _ingest_in(root, captures, **kwargs):
    return _ingest(root / ".panopticon", captures, target_root=str(root), **kwargs)


@pytest.mark.parametrize("path", [
    "tests/tooling/package-lock.json", "e2e/package-lock.json", "spec/Gemfile.lock",
    "requirements-dev.txt", "dev-requirements.txt", "requirements-test.txt",
    "test-requirements.txt", "requirements/dev.txt", "requirements/test.txt",
    "svc/api/requirements/dev.txt", "svc/requirements-dev.txt", "tests/requirements.txt",
])
def test_an_advisory_in_a_dev_only_manifest_is_marked(tmp_path, path):
    root = _tree(tmp_path, {path: "left-pad==1.0.0\n"})
    found = _ingest_in(root, {"osv-scanner.json": _osv(path)})
    assert _contexts(found) == {path: "dev_manifest"}


# ---- every file that produced the finding must be dev-only -------------------------------

DEV_PLUS_PROD = {"requirements-dev.txt": "-r requirements-prod.txt\npytest==8.0\n",
                 "requirements-prod.txt": "left-pad==1.0.0\n"}


@pytest.mark.parametrize("files, audited", [
    (DEV_PLUS_PROD, "requirements-dev.txt"),
    ({"requirements-dev.txt": "--requirement=requirements-prod.txt\n",
      "requirements-prod.txt": "x==1\n"}, "requirements-dev.txt"),
    ({"requirements-dev.txt": "-c constraints.txt\npytest\n", "constraints.txt": "x==1\n"},
     "requirements-dev.txt"),
    ({"requirements/dev.txt": "-r base.txt\npytest\n", "requirements/base.txt": "x==1\n"},
     "requirements/dev.txt"),
    ({"tests/requirements.txt": "-r ../requirements.txt\n", "requirements.txt": "x==1\n"},
     "tests/requirements.txt"),
    ({"requirements-dev.txt": "-r requirements-test.txt\n",                 # two levels down
      "requirements-test.txt": "-r requirements-prod.txt\n",
      "requirements-prod.txt": "x==1\n"}, "requirements-dev.txt"),
], ids=["dev includes prod", "the long spelling", "a constraints file", "requirements/dev.txt on base",
        "a test manifest on the root's", "prod two includes down"])
def test_a_dev_file_that_draws_on_a_file_that_is_not_dev_only_is_not_marked(tmp_path, files, audited):
    """pip-audit audits one file and follows its includes. With `requirements-dev.txt`
    (`-r requirements-prod.txt`) and no `requirements.txt`, the dev file is the one
    audited, and every PRODUCTION advisory was labelled with it."""
    root = _tree(tmp_path, files)
    for name, capture in (("osv-scanner.json", _osv(audited)), ("pip-audit.json", _pip_audit())):
        found = _ingest_in(root, {name: capture})
        (root / ".panopticon" / "tools" / name).unlink()      # one scanner's capture at a time
        # pip-audit audits a root-level file only, so its label is its own; osv-scanner's
        # is the file named. Neither finding is marked.
        assert [evidence.path_context(finding) for finding in found] == [None], name
        if name == "osv-scanner.json":
            assert found[0]["location"]["file"] == audited


@pytest.mark.parametrize("files", [
    {"requirements-dev.txt": "-r requirements-test.txt\n-c tests/constraints.txt\npytest\n",
     "requirements-test.txt": "coverage\n", "tests/constraints.txt": "x==1\n"},
    {"requirements-dev.txt": "# -r requirements-prod.txt\npytest  # -r x\n",
     "requirements-prod.txt": "x==1\n"},
], ids=["every include is dev-only", "an include in a comment"])
def test_a_dev_file_whose_includes_are_all_dev_only_is_marked(tmp_path, files):
    root = _tree(tmp_path, files)
    found = _ingest_in(root, {"osv-scanner.json": _osv("requirements-dev.txt")})
    assert _contexts(found) == {"requirements-dev.txt": "dev_manifest"}


@pytest.mark.parametrize("files, why", [
    ({}, "the audited file is not there"),
    ({"requirements-dev.txt": "-r missing.txt\n"}, "an include that is not there"),
    ({"requirements-dev.txt": "-r ../outside.txt\n"}, "an include outside the root"),
    ({"requirements-dev.txt": "-r ../dev-requirements.txt\n"},
     "an include outside the root that is named like a dev file"),
    ({"requirements-dev.txt": "-r requirements-dev.txt\n"}, "an include of itself"),
    ({"requirements-dev.txt": "-r dev-requirements.txt\n",
      "dev-requirements.txt": "-r requirements-dev.txt\n"}, "a cycle"),
    ({"requirements-dev.txt": "x" * (2 * 1024 * 1024)}, "a file too large to read whole"),
])
def test_when_the_files_read_cannot_be_told_there_is_no_mark(tmp_path, files, why):
    import scripts.tools.pip_audit as pip_audit
    root = _tree(tmp_path, files)
    for outside in ("outside.txt", "dev-requirements.txt"):
        (tmp_path / outside).write_text("x==1\n", encoding="utf-8")
    found = _ingest_in(root, {"osv-scanner.json": _osv("requirements-dev.txt")})
    assert [evidence.path_context(finding) for finding in found] == [None], why
    # Said as "cannot be told", not left to an error on the way.
    assert pip_audit.requirement_files(str(root / "requirements-dev.txt"), str(root)) is None, why


def test_a_requirements_file_is_not_dev_only_without_a_tree_to_read(tmp_path):
    """The CI gate ingests a bare directory of captures. Nothing can be read there, so
    nothing says which files produced the finding."""
    found = _ingest(tmp_path, {"osv-scanner.json": _osv("requirements-dev.txt")})
    assert _contexts(found) == {"requirements-dev.txt": None}
    lock = _ingest(tmp_path / "b", {"osv-scanner.json": _osv("tests/tooling/package-lock.json")})
    assert _contexts(lock) == {"tests/tooling/package-lock.json": "dev_manifest"}   # no includes


def test_a_dev_requirements_file_that_is_a_link_out_of_the_tree_is_not_read(tmp_path):
    root = _tree(tmp_path, {})
    (tmp_path / "elsewhere.txt").write_text("x==1\n", encoding="utf-8")
    (root / "requirements-dev.txt").symlink_to(tmp_path / "elsewhere.txt")
    found = _ingest_in(root, {"osv-scanner.json": _osv("requirements-dev.txt")})
    assert [evidence.path_context(finding) for finding in found] == [None]


@pytest.mark.parametrize("path", [
    "package-lock.json", "requirements.txt", "requirements/base.txt", "requirements/prod.txt",
    "dev.txt", "test.txt", "docs/dev.txt", "requirements-developer.txt", "xrequirements-dev.txt",
    "requirements-dev.txt.bak", "Requirements-Dev.txt", "requirements-dev/base.txt",
    "requirements/extra/dev.txt", "requirements/sub/test.txt",     # only directly inside it
])
def test_an_advisory_in_any_other_manifest_is_not_marked(tmp_path, path):
    root = tmp_path / "root"                  # the file is there to be read, and has no includes
    (root / path).parent.mkdir(parents=True)
    (root / path).write_text("left-pad==1.0.0\n", encoding="utf-8")
    (root / ".panopticon").mkdir()
    found = _ingest(root / ".panopticon", {"osv-scanner.json": _osv(path)}, target_root=str(root))
    assert _contexts(found) == {path: None}


def test_the_mark_is_added_to_what_the_scanner_said(tmp_path):
    found = _ingest(tmp_path, {"osv-scanner.json": _osv("tests/package-lock.json")})
    said = found[0]["tool_evidence"]
    assert said["path_context"] == "dev_manifest"
    assert (said["package_name"], said["rule_id"], said["ecosystem"]) == (
        "left-pad", "GHSA-aaaa-bbbb-cccc", "npm")


def test_only_an_advisory_makes_a_manifest_dev_only(tmp_path):
    """A secret in `requirements-dev.txt` is a secret in a file at the root: the name
    says what the file's DEPENDENCIES are for, nothing about anything else in it."""
    root = tmp_path / "root"
    (root / "tests").mkdir(parents=True)
    (root / ".panopticon").mkdir()
    for path in ("requirements-dev.txt", "tests/requirements-dev.txt"):
        (root / path).write_text("left-pad==1.0.0\n", encoding="utf-8")
    found = _ingest(root / ".panopticon", {
        "gitleaks.sarif": _sarif("gitleaks", "requirements-dev.txt", "tests/requirements-dev.txt",
                                 rule="generic-api-key", level=None)}, target_root=str(root))
    assert _contexts(found) == {"requirements-dev.txt": None,
                                "tests/requirements-dev.txt": "test"}


def test_a_review_root_that_sits_under_a_test_directory_marks_nothing_by_that(tmp_path):
    """Only the path inside the review root counts: a project checked out at
    `.../tests/proj` is not a project of tests."""
    root = tmp_path / "tests" / "e2e" / "proj"
    (root / ".panopticon").mkdir(parents=True)
    absolute = str(root / "src" / "app.py").lstrip("/")      # a scanner that reports host paths
    found = _ingest(root / ".panopticon", {
        "semgrep.sarif": _sarif("semgrep", "src/app.py", "lib/tests/a.py", absolute)},
        target_root=str(root))
    assert [(finding.get("tool_evidence") or {}).get("path_context") for finding in found] == [
        None, "test", None]


def test_the_mark_is_not_part_of_a_findings_identity(tmp_path):
    found = _ingest(tmp_path, {"semgrep.sarif": _sarif("semgrep", "tests/a.py")})
    marked = found[0]
    bare = dict(marked, tool_evidence={key: value for key, value in marked["tool_evidence"].items()
                                       if key != "path_context"})
    assert marked["tool_evidence"]["path_context"] == "test"
    assert evidence.finding_fingerprint(marked) == evidence.finding_fingerprint(bare)
    assert evidence.reconcile_key(marked) == evidence.reconcile_key(bare)


def test_only_a_scanner_finding_carries_the_fact():
    """An agent's own finding cannot assert the mark and leave the gate by it."""
    agent = {"source": "agent", "tool_evidence": {"path_context": "test"},
             "location": {"file": "tests/a.py"}}
    tool = dict(agent, source="tool:semgrep")
    assert evidence.path_context(agent) is None
    assert evidence.path_context(tool) == "test"
    assert evidence.path_context(dict(tool, tool_evidence={"path_context": "somewhere"})) is None
    assert evidence.path_context(dict(tool, tool_evidence="test")) is None


# ---- the rule, through to the report ---------------------------------------------------

def _report(tmp_path, monkeypatch, captures, verdict, security="standard", fail_on="high",
            groups=None, reviewer=(), root=False):
    """Both real passes of `synthesize`: the verify queue, then every scanner claim
    answered `verdict` by the advisor."""
    tmp_path.mkdir(exist_ok=True)
    monkeypatch.chdir(tmp_path)
    adopt_panopticon(str(tmp_path))
    tools = tmp_path / "tools"
    tools.mkdir()
    for name, document in captures.items():
        (tools / name).write_text(json.dumps(document), encoding="utf-8")
    agent = tmp_path / "findings-g1-SEC.json"
    agent.write_text(json.dumps({"findings": list(reviewer)}), encoding="utf-8")
    common = ["--repo", "--target", "src", "--tools-dir", str(tools), "--fail-on", fail_on]
    if root:                              # the reviewed tree is this directory
        common += ["--root", str(tmp_path)]
    if security is not None:
        common += ["--security", security]
    if groups is not None:                # the TARGET's own record of the run
        (tmp_path / ".panopticon" / "groups.json").write_text(json.dumps(groups), encoding="utf-8")
        common += ["--groups", str(tmp_path / ".panopticon" / "groups.json")]
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        assert _fresh(synthesize.main, common + ["--emit-verify-queue", "--out",
                                                 str(tmp_path / "unused.json"), str(agent)]) == 0
    queue = json.loads((tmp_path / ".panopticon" / "verify-queue.json").read_text(encoding="utf-8"))
    verdicts = tmp_path / "verdicts"
    verdicts.mkdir()
    for entry in queue["entries"]:
        (verdicts / ("%s.json" % entry["queue_id"])).write_text(json.dumps({
            "run_id": queue["run_id"], "finding_id": entry["finding"].get("id"),
            "verdict": verdict, "reasoning": "the advisor's own words"}), encoding="utf-8")
    out, said = tmp_path / "report.json", io.StringIO()
    with contextlib.redirect_stdout(said), contextlib.redirect_stderr(io.StringIO()):
        _fresh(synthesize.main,
               common + ["--verdicts-dir", str(verdicts), "--out", str(out), str(agent)])
    report = json.loads(out.read_text(encoding="utf-8"))
    report["_said"] = said.getvalue()
    report["_page"] = (tmp_path / "report.json.html").read_text(encoding="utf-8")
    return report


def _standing(report):
    summary = report["summary"]
    return (summary["gate"], summary["overall_grade"], summary["provisional_grade"],
            summary["health"], summary["risk_level"])


#: What the gate reads when nothing fails it HERE: a bare `synthesize` call has no
#: review plan to certify, so it is INCONCLUSIVE where a full run would PASS.
QUIET = "INCONCLUSIVE"


SECRET = {"gitleaks.sarif": _sarif("gitleaks", "tests/keys/id_rsa", rule="private-key", level=None)}
ADVISORY = {"osv-scanner.json": _osv("tests/tooling/package-lock.json")}
ELSEWHERE = {"gitleaks.sarif": _sarif("gitleaks", "src/keys/id_rsa", rule="private-key", level=None)}


@pytest.mark.parametrize("captures, rule", [(SECRET, "test-path"), (ADVISORY, "dev-manifest")],
                         ids=["a secret under a test directory", "an advisory in a dev-only lockfile"])
def test_in_standard_mode_it_is_reported_and_the_verdict_does_not_move_the_gate(
        tmp_path, monkeypatch, captures, rule):
    """The issue's two cases. Confirmed in five runs and rejected in one, the run that
    rejected it graded two bands higher."""
    confirmed = _report(tmp_path / "confirmed", monkeypatch, captures, "CONFIRMED")
    rejected = _report(tmp_path / "rejected", monkeypatch, captures, "REJECTED")
    assert _standing(confirmed) == _standing(rejected)
    assert confirmed["summary"]["gate"] == QUIET
    assert [(row["evidence"]["status"], row.get("gate")) for row in confirmed["findings"]] == [
        ("tool_confirmed", {"eligible": False, "rule": rule})]
    assert rejected["findings"] == [] and len(rejected["discarded_claims"]) == 1
    assert confirmed["meta"]["coverage"]["tools_context_not_gated"] == {rule: 1}
    assert rejected["meta"]["coverage"]["tools_context_not_gated"] == {}
    line = ("1 scanner finding in a test path or dev-only manifest is reported and not counted "
            "toward the gate, grade or health (")
    assert line + "%s: 1)" % rule in confirmed["_said"]
    assert line + "<code>%s</code>: 1)" % rule in confirmed["_page"]
    for quiet in (rejected["_said"], rejected["_page"]):
        assert "not counted toward the gate" not in quiet


def test_the_same_finding_anywhere_else_still_decides_the_gate(tmp_path, monkeypatch):
    confirmed = _report(tmp_path / "confirmed", monkeypatch, ELSEWHERE, "CONFIRMED")
    rejected = _report(tmp_path / "rejected", monkeypatch, ELSEWHERE, "REJECTED")
    assert (confirmed["summary"]["gate"], rejected["summary"]["gate"]) == ("FAIL", QUIET)
    assert "gate" not in confirmed["findings"][0]
    assert confirmed["meta"]["coverage"]["tools_context_not_gated"] == {}


@pytest.mark.parametrize("captures", [SECRET, ADVISORY],
                         ids=["a secret (secret-class)", "an advisory (CRITICAL)"])
def test_in_redteam_a_critical_or_secret_finding_there_counts(tmp_path, monkeypatch, captures):
    confirmed = _report(tmp_path / "confirmed", monkeypatch, captures, "CONFIRMED", "redteam")
    rejected = _report(tmp_path / "rejected", monkeypatch, captures, "REJECTED", "redteam")
    assert (confirmed["summary"]["gate"], rejected["summary"]["gate"]) == ("FAIL", QUIET)
    assert "gate" not in confirmed["findings"][0]              # counted like any other
    assert confirmed["meta"]["coverage"]["tools_context_not_gated"] == {}


def test_in_redteam_anything_less_there_is_reported_and_not_counted(tmp_path, monkeypatch):
    """#1578's rule itself: a HIGH that is not a secret does not drive a gate from a
    directory the project does not ship."""
    high = {"osv-scanner.json": _osv("tests/tooling/package-lock.json", severity="HIGH"),
            "semgrep.sarif": _sarif("semgrep", "tests/unit/test_auth.py")}
    report = _report(tmp_path, monkeypatch, high, "CONFIRMED", "redteam")
    assert report["summary"]["gate"] == QUIET
    assert sorted((row["severity"], row["gate"]["rule"]) for row in report["findings"]) == [
        ("HIGH", "dev-manifest"), ("HIGH", "test-path")]
    assert report["meta"]["coverage"]["tools_context_not_gated"] == {
        "dev-manifest": 1, "test-path": 1}
    line = ("2 scanner findings in a test path or dev-only manifest are reported and not "
            "counted toward the gate, grade or health (")
    assert line + "dev-manifest: 1; test-path: 1)" in report["_said"]
    assert line + "<code>dev-manifest</code>: 1; <code>test-path</code>: 1)" in report["_page"]


def test_the_rule_is_the_suppressed_rule_itself(tmp_path, monkeypatch):
    """Not a copy of it: change #1578's answer and this gate follows."""
    from unittest import mock
    with mock.patch.object(it, "gates_when_suppressed", return_value=False) as asked:
        report = _report(tmp_path, monkeypatch, SECRET, "CONFIRMED", "redteam")
    assert report["summary"]["gate"] == QUIET
    assert asked.called and report["findings"][0]["gate"] == {"eligible": False, "rule": "test-path"}


# ---- the advisor is told ---------------------------------------------------------------

def test_the_advisor_prompt_says_the_fact_is_settled():
    import scripts.dispatch as dispatch
    claim = json.dumps({"id": "T-1", "source": "tool:gitleaks",
                        "tool_evidence": {"path_context": "test"},
                        "location": {"file": "tests/keys/id_rsa", "line_start": 1}})
    prompt = dispatch.render_prompt("advisor.md", {"claim_json": claim}, "claude")
    assert '"path_context": "test"' in prompt
    rule = [line for line in prompt.splitlines() if "tool_evidence.path_context" in line]
    assert len(rule) == 1
    for said in ("`test` or `dev_manifest`", "the controller has already established",
                 "not grounds to REJECT and not grounds to CONFIRM",
                 'the "test scaffolding" question above does not apply',
                 "Judge only whether the claim is true of what is at the location"):
        assert said in rule[0], said


def test_the_claim_the_driver_hands_the_advisor_carries_the_fact(tmp_path):
    """The driver's own tool queue ingests through the same point as both synthesize
    passes, so the claim it renders has the mark."""
    found = _ingest(tmp_path, {
        "gitleaks.sarif": _sarif("gitleaks", "tests/keys/id_rsa", rule="private-key", level=None),
        "osv-scanner.json": _osv("e2e/package-lock.json")})
    assert sorted((evidence.tool_name(finding), evidence.path_context(finding))
                  for finding in found) == [("gitleaks", "test"), ("osv-scanner", "dev_manifest")]
    for finding in found:                 # and it survives the round trip a claim makes
        assert evidence.path_context(json.loads(json.dumps(finding))) == evidence.path_context(finding)


def test_the_report_validates_with_the_new_fields(tmp_path, monkeypatch):
    import scripts.synth.validate_schema as validate_schema
    report = _report(tmp_path, monkeypatch, dict(SECRET, **ADVISORY), "CONFIRMED")
    report.pop("_said"), report.pop("_page")
    assert validate_schema.schema_errors(report) == []
    assert sorted(row["tool_evidence"]["path_context"] for row in report["findings"]) == [
        "dev_manifest", "test"]


def test_a_report_from_before_the_rule_renders_no_line():
    import scripts.html_report as html_report
    import scripts.synth.render as render
    for counts in (None, {}, {"test-path": 0}, {"test-path": "lots"}, ["test-path"], {7: 1}):
        assert render._context_not_gated_line(counts) == ""
        assert html_report._render_context_not_gated({"coverage": {"tools_context_not_gated": counts}}) == ""
    assert html_report._render_context_not_gated({}) == ""



def test_the_mode_that_decides_is_the_gates_own_never_the_targets(tmp_path, monkeypatch):
    """`groups.json` is written into the reviewed tree. It may say `redteam`; the rule
    reads the mode the operator gave (#1707), and with none given that is standard."""
    says_redteam = {"mode": "repo", "groups": [], "security_mode": "redteam"}
    report = _report(tmp_path, monkeypatch, SECRET, "CONFIRMED", security=None, groups=says_redteam)
    assert (report["meta"]["security_mode"], report["meta"]["gate_security_mode"]) == (
        "redteam", "standard")
    assert report["summary"]["gate"] == QUIET
    assert report["findings"][0]["gate"] == {"eligible": False, "rule": "test-path"}


@pytest.mark.parametrize("claimed", ["CRITICAL", "HIGH", "MEDIUM"])
def test_a_reviewers_own_claim_at_the_same_line_does_not_change_the_scanner_rows_standing(
        tmp_path, monkeypatch, claimed):
    """A scanner finding and one reviewer claim at one line were made one row, the more
    severe of the two. A reviewer's claim varies from run to run, so the scanner finding
    was out of the gate in one run and, absorbed into the claim, in it in the next; and a
    confirmed claim absorbed the other way left the gate with it. They stay two rows:
    the scanner's keeps its mark, the reviewer's stands on its own (as #3649 ruled for a
    first-party advisory)."""
    claim = {"id": "A-1", "title": "private key committed", "severity": claimed,
             "confidence": "CERTAIN", "panel": "security", "category": "secrets",
             "location": {"file": "tests/keys/id_rsa", "line_start": 1}}
    report = _report(tmp_path, monkeypatch, SECRET, "CONFIRMED", reviewer=[claim])
    rows = sorted(report["findings"], key=lambda row: str(row.get("source")))
    assert [(str(row.get("source")).startswith("tool:"), row["severity"], row.get("gate"))
            for row in rows] == [
        (False, claimed, None),
        (True, "HIGH", {"eligible": False, "rule": "test-path"})]
    assert report["summary"]["gate"] == ("FAIL" if claimed in ("CRITICAL", "HIGH") else QUIET)
    assert report["meta"]["coverage"]["tools_context_not_gated"] == {"test-path": 1}


def test_elsewhere_a_scanner_finding_and_one_claim_are_still_one_row(tmp_path, monkeypatch):
    claim = {"id": "A-1", "title": "private key committed", "severity": "MEDIUM",
             "confidence": "CERTAIN", "panel": "security", "category": "secrets",
             "location": {"file": "src/keys/id_rsa", "line_start": 1}}
    report = _report(tmp_path, monkeypatch, ELSEWHERE, "CONFIRMED", reviewer=[claim])
    assert [(row["source"], row.get("reinforced")) for row in report["findings"]] == [
        ("tool:gitleaks", True)]


def test_the_dev_plus_prod_layout_fails_the_standard_gate(tmp_path, monkeypatch):
    """The coordinator's case, through to the gate: `requirements-dev.txt` includes
    `requirements-prod.txt`, there is no `requirements.txt`, and pip-audit's CRITICAL is
    labelled with the dev file. It is a production advisory: no mark, and the gate FAILs."""
    for path, text in DEV_PLUS_PROD.items():
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_text(text, encoding="utf-8")
    report = _report(tmp_path, monkeypatch, {"pip-audit.json": _pip_audit()}, "CONFIRMED",
                     fail_on="critical", root=True)
    assert [(row["location"]["file"], row["severity"], row.get("gate"),
             row["tool_evidence"].get("path_context")) for row in report["findings"]] == [
        ("requirements-dev.txt", "CRITICAL", None, None)]
    assert report["summary"]["gate"] == "FAIL"
    assert report["meta"]["coverage"]["tools_context_not_gated"] == {}


def test_a_project_whose_only_requirements_file_is_the_dev_one_is_marked(tmp_path, monkeypatch):
    (tmp_path / "requirements-dev.txt").write_text("left-pad==1.0.0\n", encoding="utf-8")
    report = _report(tmp_path, monkeypatch, {"pip-audit.json": _pip_audit()}, "CONFIRMED",
                     fail_on="critical", root=True)
    assert [(row["location"]["file"], row.get("gate")) for row in report["findings"]] == [
        ("requirements-dev.txt", {"eligible": False, "rule": "dev-manifest"})]
    assert report["summary"]["gate"] == QUIET


def test_more_included_files_than_the_bound_is_not_told(tmp_path):
    import scripts.tools.pip_audit as pip_audit
    names = ["tests/req-%02d.txt" % n for n in range(pip_audit._MAX_CLOSURE_FILES + 1)]
    for count, marked in ((pip_audit._MAX_CLOSURE_FILES - 1, "dev_manifest"),
                          (pip_audit._MAX_CLOSURE_FILES, None)):
        root = _tree(tmp_path / str(count), dict(
            {"requirements-dev.txt": "".join("-r %s\n" % name for name in names[:count])},
            **{name: "x==1\n" for name in names[:count]}))
        found = _ingest_in(root, {"osv-scanner.json": _osv("requirements-dev.txt")})
        assert [evidence.path_context(finding) for finding in found] == [marked], count
        told = pip_audit.requirement_files(str(root / "requirements-dev.txt"), str(root))
        assert (told is None) == (marked is None)
        if told is not None:
            assert told == sorted(["requirements-dev.txt"] + names[:count])


def test_a_pip_audit_capture_is_labelled_from_its_own_tree_whatever_ran_before(tmp_path):
    """The order dependence this file's helpers guard against, shown on purpose: with
    another test's choice left in the context, the label is that test's."""
    import scripts.tools.pip_audit as pip_audit
    root = _tree(tmp_path, DEV_PLUS_PROD)

    def after_another_tests_invoke():
        pip_audit._manifest_path_cv.set("requirements.txt")
        return it.ingest_dir_detailed(str(root / ".panopticon" / "tools"), "g1",
                                      target_root=str(root))[0]

    (root / ".panopticon" / "tools").mkdir()
    (root / ".panopticon" / "tools" / "pip-audit.json").write_text(
        json.dumps(_pip_audit()), encoding="utf-8")
    with contextlib.redirect_stderr(io.StringIO()):
        stale = contextvars.Context().run(after_another_tests_invoke)
    own = _ingest_in(root, {"pip-audit.json": _pip_audit()})
    assert [finding["location"]["file"] for finding in stale] == ["requirements.txt"]
    assert [finding["location"]["file"] for finding in own] == ["requirements-dev.txt"]
    assert [evidence.path_context(finding) for finding in stale + own] == [None, None]


# ---- seat review of #3789 at 63951780 -------------------------------------------------

def test_an_include_that_is_not_a_regular_file_is_not_opened(tmp_path):
    """A FIFO included from a dev file hung ingest: the reader opened whatever was there.
    It is "cannot be told", at once."""
    import os
    import threading
    import scripts.tools.pip_audit as pip_audit
    root = _tree(tmp_path, {"requirements-dev.txt": "-r pipe.txt\npytest\n"})
    os.mkfifo(root / "pipe.txt")
    (root / "adir.txt").mkdir()
    told = []
    reader = threading.Thread(target=lambda: told.append(
        pip_audit.requirement_files(str(root / "requirements-dev.txt"), str(root))), daemon=True)
    reader.start()
    reader.join(10)
    assert not reader.is_alive(), "the walk is waiting on a FIFO"
    assert told == [None]
    found = _ingest_in(root, {"osv-scanner.json": _osv("requirements-dev.txt")})
    assert [evidence.path_context(finding) for finding in found] == [None]
    (root / "requirements-test.txt").write_text("-r adir.txt\n", encoding="utf-8")
    assert pip_audit.requirement_files(str(root / "requirements-test.txt"), str(root)) is None
    assert pip_audit.requirement_files(str(root / "pipe.txt"), str(root)) is None


def test_a_manifests_includes_are_read_once_for_all_its_findings(tmp_path):
    import scripts.tools.pip_audit as pip_audit
    from unittest import mock
    root = _tree(tmp_path, {"requirements-dev.txt": "-r requirements-test.txt\n",
                            "requirements-test.txt": "x==1\n", "dev-requirements.txt": "y==1\n"})
    document = {"results": [
        {"source": {"path": "/src/requirements-dev.txt"}, "packages": [
            {"package": {"name": "p%d" % n, "version": "1.0", "ecosystem": "PyPI"},
             "vulnerabilities": [{"id": "GHSA-%04d" % n, "summary": "s",
                                  "database_specific": {"severity": "HIGH"}}], "groups": []}
            for n in range(30)]},
        {"source": {"path": "/src/dev-requirements.txt"}, "packages": [
            {"package": {"name": "q", "version": "1.0", "ecosystem": "PyPI"},
             "vulnerabilities": [{"id": "GHSA-q", "summary": "s",
                                  "database_specific": {"severity": "HIGH"}}], "groups": []}]}]}
    with mock.patch.object(pip_audit, "_requirement_closure",
                           wraps=pip_audit._requirement_closure) as walked:
        found = _ingest_in(root, {"osv-scanner.json": document})
    assert [evidence.path_context(finding) for finding in found] == ["dev_manifest"] * 31
    assert walked.call_count == 2                     # once per manifest, not once per finding


@pytest.mark.parametrize("line", [
    "-rrequirements-prod.txt", "-crequirements-prod.txt", "-R requirements-prod.txt",
    "-Rrequirements-prod.txt", "--requirement", "--constraint", "-r", "-c",
    "--requirement:requirements-prod.txt", "--requirements requirements-prod.txt",
])
def test_an_include_spelled_in_a_way_the_walker_does_not_read_is_not_told(tmp_path, line):
    """`-rprod.txt` is an include to pip. Read as "no include", a dev file holding it was
    marked while it drew on production's file."""
    import scripts.tools.pip_audit as pip_audit
    root = _tree(tmp_path, {"requirements-dev.txt": "pytest\n%s\n" % line,
                            "requirements-prod.txt": "x==1\n"})
    assert pip_audit.requirement_files(str(root / "requirements-dev.txt"), str(root)) is None
    found = _ingest_in(root, {"osv-scanner.json": _osv("requirements-dev.txt")})
    assert [evidence.path_context(finding) for finding in found] == [None]


@pytest.mark.parametrize("line", [
    "--index-url https://example.invalid/simple", "--extra-index-url https://example.invalid",
    "-e ./local", "--hash=sha256:abc", "-f wheels/", "--no-binary :all:", "--pre",
    "requests  # -r requirements-prod.txt", "# -rrequirements-prod.txt", "--config-settings x=y",
])
def test_another_option_is_not_taken_for_an_include(tmp_path, line):
    root = _tree(tmp_path, {"requirements-dev.txt": "pytest\n%s\n" % line,
                            "requirements-prod.txt": "x==1\n"})
    found = _ingest_in(root, {"osv-scanner.json": _osv("requirements-dev.txt")})
    assert [evidence.path_context(finding) for finding in found] == ["dev_manifest"]


def test_an_included_file_is_judged_by_where_it_really_is(tmp_path):
    """`requirements-test.txt` that is a link to production's file is production's file."""
    root = _tree(tmp_path, {"requirements-dev.txt": "-r requirements-test.txt\n-r tests/reqs/a.txt\n",
                            "requirements-prod.txt": "x==1\n", "tests/reqs/a.txt": "y==1\n"})
    (root / "requirements-test.txt").symlink_to("requirements-prod.txt")
    found = _ingest_in(root, {"osv-scanner.json": _osv("requirements-dev.txt")})
    assert [evidence.path_context(finding) for finding in found] == [None]
    (root / "requirements-test.txt").unlink()
    (root / "requirements-test.txt").symlink_to("tests/reqs/a.txt")       # a link to a dev file
    found = _ingest_in(root, {"osv-scanner.json": _osv("requirements-dev.txt")})
    assert [evidence.path_context(finding) for finding in found] == ["dev_manifest"]
    (root / "prod-reqs").mkdir()
    (root / "prod-reqs" / "a.txt").write_text("z==1\n", encoding="utf-8")
    (root / "tests" / "linked").symlink_to("../prod-reqs")                # a linked DIRECTORY
    (root / "requirements-dev.txt").write_text("-r tests/linked/a.txt\n", encoding="utf-8")
    found = _ingest_in(root, {"osv-scanner.json": _osv("requirements-dev.txt")})
    assert [evidence.path_context(finding) for finding in found] == [None]


def test_a_root_reached_through_a_link_is_stripped_by_where_it_really_is(tmp_path):
    """The root is really under `tests/e2e/`, it is given by an alias that is not, and the
    scanner reports the real path: still a path inside the root, and nothing is marked."""
    real = tmp_path / "tests" / "e2e" / "proj"
    (real / ".panopticon").mkdir(parents=True)
    alias = tmp_path / "alias"
    alias.symlink_to(real)
    reported = str(real / "src" / "app.py").lstrip("/")
    assert "tests/e2e" in reported and "tests" not in str(alias)
    found = _ingest(alias / ".panopticon", {"semgrep.sarif": _sarif("semgrep", reported)},
                    target_root=str(alias))
    assert [evidence.path_context(finding) for finding in found] == [None]


def _trivy(uri, *, secret, text="Package: left-pad\nInstalled Version: 1.0.0\nVulnerability CVE-2099-1"):
    tags = ["secret", "security", "HIGH"] if secret else ["vulnerability", "security", "HIGH"]
    return {"runs": [{
        "tool": {"driver": {"name": "trivy", "rules": [{
            "id": "CVE-2099-1", "properties": {"security-severity": "8.0", "tags": tags}}]}},
        "results": [{"ruleId": "CVE-2099-1", "level": "error", "message": {"text": text},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": uri}, "region": {"startLine": 1}}}]}]}]}


def test_a_trivy_secret_in_a_dev_named_file_is_never_a_dev_manifest(tmp_path):
    """Only its advisories are advisories. A secret in `requirements-dev.txt` is a
    secret in a file at the root, whatever its message says about packages."""
    root = _tree(tmp_path, {"requirements-dev.txt": "left-pad==1.0.0\n",
                            "tests/package-lock.json": "{}"})
    for uri, secret, expected in (
            ("requirements-dev.txt", True, None),
            ("requirements-dev.txt", False, "dev_manifest"),
            ("tests/package-lock.json", True, "test"),
            ("tests/package-lock.json", False, "dev_manifest")):
        found = _ingest_in(root, {"trivy.sarif": _trivy(uri, secret=secret)})
        assert [evidence.path_context(finding) for finding in found] == [expected], (uri, secret)


def test_a_reviewer_cannot_write_the_gate_marker_on_its_own_finding(tmp_path, monkeypatch):
    """An agent CRITICAL that said `gate: {eligible: false}` of itself was published so,
    on a row that failed the gate."""
    claim = {"id": "A-1", "title": "auth bypass", "severity": "CRITICAL", "confidence": "CERTAIN",
             "panel": "security", "category": "auth", "location": {"file": "src/app.py", "line_start": 3},
             "gate": {"eligible": False, "rule": "test-path"},
             "tool_evidence": {"path_context": "test"}}
    report = _report(tmp_path, monkeypatch, {}, "CONFIRMED", reviewer=[claim])
    assert report["summary"]["gate"] == "FAIL"
    assert [("gate" in row, row["severity"]) for row in report["findings"]] == [(False, "CRITICAL")]
    assert report["meta"]["coverage"]["tools_context_not_gated"] == {}


def test_the_marker_and_the_count_are_of_rows_the_rule_took_out(tmp_path, monkeypatch):
    """A marked finding no advisor answered is out of the gate on its evidence, as it
    would be anywhere. The rule did not take it out, so it is not counted as if it had."""
    monkeypatch.chdir(tmp_path)
    adopt_panopticon(str(tmp_path))
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "gitleaks.sarif").write_text(json.dumps(SECRET["gitleaks.sarif"]), encoding="utf-8")
    out = tmp_path / "report.json"
    for extra, counted in (((), {}), (("--gate-unverified",), {"test-path": 1})):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            _fresh(synthesize.main, ["--repo", "--target", "src", "--tools-dir", str(tools),
                                     "--out", str(out), *extra])
        report = json.loads(out.read_text(encoding="utf-8"))
        row = report["findings"][0]
        assert (row["evidence"]["status"], row["tool_evidence"]["path_context"]) == (
            "tool_reported", "test")
        assert report["meta"]["coverage"]["tools_context_not_gated"] == counted, extra
        assert row.get("gate") == ({"eligible": False, "rule": "test-path"} if counted else None)
