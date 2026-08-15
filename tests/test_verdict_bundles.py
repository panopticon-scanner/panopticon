import json
import evidence


def _bundle(tmp_path, name, verdicts, stage="primary", run_id="R"):
    d = tmp_path / "verdicts"
    d.mkdir(exist_ok=True)
    (d / name).write_text(json.dumps({
        "verdicts": verdicts,
        "_panopticon": {"run_id": run_id, "role": "domain_advisor",
                        "domain": "SEC", "group": "app", "stage": stage}}))
    return str(d)


def test_bundle_flattens_by_finding_id(tmp_path):
    d = _bundle(tmp_path, "verdicts-app-SEC.json",
                [{"finding_id": "SEC-100", "verdict": "CONFIRMED", "reasoning": "x"},
                 {"finding_id": "SEC-200", "verdict": "REJECTED", "reasoning": "y"}])
    by_fid, bad = evidence.load_verdict_bundles(d)
    assert bad == []
    assert by_fid["SEC-100"]["verdict"] == "CONFIRMED"
    assert by_fid["SEC-100"]["run_id"] == "R"       # run_id pushed down from bundle
    assert by_fid["SEC-100"]["stage"] == "primary"


def test_backup_overrides_primary_for_same_finding(tmp_path):
    _bundle(tmp_path, "verdicts-app-SEC.json",
            [{"finding_id": "SEC-100", "verdict": "CONFIRMED"}], stage="primary")
    d = _bundle(tmp_path, "verdicts-app-SEC-backup.json",
                [{"finding_id": "SEC-100", "verdict": "REJECTED"}], stage="backup")
    by_fid, _ = evidence.load_verdict_bundles(d)
    assert by_fid["SEC-100"]["verdict"] == "REJECTED"
    assert by_fid["SEC-100"]["stage"] == "backup"


def test_match_by_id_enforces_run_id(tmp_path):
    d = _bundle(tmp_path, "verdicts-app-SEC.json",
                [{"finding_id": "SEC-100", "verdict": "CONFIRMED"}], run_id="R")
    by_fid, _ = evidence.load_verdict_bundles(d)
    f = {"id": "SEC-100"}
    assert evidence.match_verdict_by_id(f, by_fid, run_id="R")["verdict"] == "CONFIRMED"
    assert evidence.match_verdict_by_id(f, by_fid, run_id="OTHER") is None
    assert evidence.match_verdict_by_id({"id": "SEC-999"}, by_fid, run_id="R") is None


def test_single_verdict_files_are_not_bundles(tmp_path):
    d = tmp_path / "verdicts"; d.mkdir()
    (d / "abc123.json").write_text(json.dumps(
        {"finding_id": "SEC-1", "verdict": "CONFIRMED"}))   # legacy single file
    by_fid, bad = evidence.load_verdict_bundles(str(d))
    assert by_fid == {} and bad == []                       # ignored, not unloadable


def test_build_report_binds_bundle_verdict_by_finding_id(tmp_path):
    import synthesize
    fp = tmp_path / "findings-app-SEC.json"
    fp.write_text(json.dumps({"findings": [
        {"domain": "SEC", "code": "SEC-A1A", "severity": "HIGH",
         "title": "authz bypass", "description": "x",
         "location": {"file": "app/x.py", "line_start": 4}, "category": "authz"}]}))
    findings = synthesize.load_findings([str(fp)])
    fid = findings[0]["id"]
    d = _bundle(tmp_path, "verdicts-app-SEC.json",
                [{"finding_id": fid, "verdict": "CONFIRMED", "reasoning": "ok"}],
                run_id="R")
    by_fid, _ = evidence.load_verdict_bundles(d)
    report = synthesize.build_report(findings, [], "src", "high",
                                     "2026-08-15T00:00:00Z",
                                     verdicts={}, verdict_bundles=by_fid,
                                     verdicts_supplied=True, verdict_run_id="R")
    assert report["findings"][0]["evidence"]["status"] == "advisor_confirmed"
