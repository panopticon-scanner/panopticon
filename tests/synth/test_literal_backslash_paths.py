"""#2988: POSIX filename bytes must not select another tree's path policy."""
from copy import deepcopy
import json
import os

import pytest

import scripts.diff_map as diff_map
import scripts.evidence as evidence
import scripts.synthesize as synthesize


def _finding(path):
    return {
        "id": "CD-001", "domain": "COD", "title": "Unsafe deserializer executes code",
        "severity": "HIGH", "confidence": "LIKELY", "panel": "code", "category": "logic",
        "location": {"file": path, "line_start": 1},
    }


def _report(root, spelling, files):
    for name in files:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("value = 1\n" * 20)
    groups = root / "groups.json"
    groups.write_text(json.dumps({"mode": "repo", "groups": [
        {"id": "g1", "name": "source", "files": files}]}))
    findings = root / "findings-g1-COD.json"
    findings.write_text(json.dumps({"findings": [_finding(spelling)]}))
    out = root / "report.json"
    rc = synthesize.main([
        "--repo", "--root", str(root), "--target", str(root), "--groups", str(groups),
        "--security", "standard", "--fail-on", "high", "--gate-unverified",
        "--out", str(out), str(findings),
    ])
    return rc, json.loads(out.read_text())


@pytest.mark.skipif(os.name == "nt", reason="backslash is a literal filename byte on POSIX")
@pytest.mark.parametrize("spelling", [r"docs\x.py", r"plans\x.py", r"project\specs/x.py"])
def test_real_report_keeps_literal_backslash_high_and_fails(tmp_path, spelling):
    rc, report = _report(tmp_path, spelling, [spelling])
    assert (tmp_path / spelling).is_file()
    assert not (tmp_path / spelling.replace("\\", "/")).exists()
    assert report["findings"][0]["location"]["file"] == spelling
    assert report["findings"][0]["severity"] == "HIGH"
    assert report["meta"]["coverage"]["doc_policy"]["downgraded"] == 0
    assert report["summary"]["gate"] == "FAIL"
    assert rc == 1


@pytest.mark.parametrize("spelling", ["docs/x.py", "plans/x.py", "project/specs/x.py"])
def test_real_report_preserves_actual_doc_tree_policy(tmp_path, spelling):
    rc, report = _report(tmp_path, spelling, [spelling])
    assert report["findings"][0]["severity"] == "INFO"
    assert report["findings"][0]["doc_policy"]["downgraded_from"] == "HIGH"
    assert report["meta"]["coverage"]["doc_policy"]["downgraded"] == 1
    assert report["summary"]["gate"] == "PASS"
    assert rc == 0


def test_unplaceable_backslash_name_cannot_borrow_doc_policy(tmp_path):
    rc, report = _report(tmp_path, r"docs\missing.py", ["src.py"])
    assert not (tmp_path / r"docs\missing.py").exists()
    assert report["findings"][0]["severity"] == "HIGH"
    assert report["summary"]["gate"] == "FAIL"
    assert rc == 1


def test_finding_identities_distinguish_literal_backslash_from_separator():
    literal = _finding(r"src\x.py")
    nested = deepcopy(literal)
    nested["location"]["file"] = "src/x.py"
    assert evidence.finding_fingerprint(literal) != evidence.finding_fingerprint(nested)
    assert evidence.matrix_finding_id(literal) != evidence.matrix_finding_id(nested)
    assert evidence.reconcile_key(literal) != evidence.reconcile_key(nested)


@pytest.mark.skipif(os.name == "nt", reason="backslash is a literal filename byte on POSIX")
@pytest.mark.parametrize("absolute", [False, True])
@pytest.mark.parametrize("spelling", [r"src\x.py", "src/x.py"])
def test_diff_gate_matches_only_the_actual_filename(tmp_path, absolute, spelling):
    other = "src/x.py" if spelling == r"src\x.py" else r"src\x.py"
    for name in (spelling, other):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("value = 1\n")
    location = str(tmp_path / spelling) if absolute else spelling
    finding = _finding(location)
    assert diff_map.classify(finding, {spelling: [(1, 1)]},
                             repo_root=str(tmp_path))["on_diff"]
    assert not diff_map.classify(finding, {other: [(1, 1)]},
                                 repo_root=str(tmp_path))["on_diff"]
    assert diff_map.norm_key(location, str(tmp_path)) == spelling
