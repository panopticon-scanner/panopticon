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
    v = evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid, run_id="R")
    assert v["verdict"] == "CONFIRMED"
    assert v["run_id"] == "R"       # run_id pushed down from bundle
    assert v["stage"] == "primary"


def test_backup_overrides_primary_for_same_finding(tmp_path):
    _bundle(tmp_path, "verdicts-app-SEC.json",
            [{"finding_id": "SEC-100", "verdict": "CONFIRMED"}], stage="primary")
    d = _bundle(tmp_path, "verdicts-app-SEC-backup.json",
                [{"finding_id": "SEC-100", "verdict": "REJECTED"}], stage="backup")
    by_fid, _ = evidence.load_verdict_bundles(d)
    v = evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid, run_id="R")
    assert v["verdict"] == "REJECTED"
    assert v["stage"] == "backup"


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


def test_queue_id_match_not_overwritten_by_fid_bundle(tmp_path):
    import synthesize
    fp = tmp_path / "findings-app-SEC.json"
    fp.write_text(json.dumps({"findings": [
        {"domain": "SEC", "code": "SEC-A1A", "severity": "HIGH", "title": "authz",
         "description": "x", "location": {"file": "app/x.py", "line_start": 4},
         "category": "authz"}]}))
    findings = synthesize.load_findings([str(fp)])
    fid = findings[0]["id"]
    qid = evidence.finding_fingerprint(findings[0])
    verdicts = {qid: {"finding_id": fid, "verdict": "REJECTED"}}          # queue_id path
    by_fid = {fid: [{"finding_id": fid, "verdict": "CONFIRMED", "run_id": None}]}  # fid path
    report = synthesize.build_report(findings, [], "src", "high",
                                     "2026-08-15T00:00:00Z", verdicts=verdicts,
                                     verdict_bundles=by_fid, verdicts_supplied=True)
    # A REJECTED finding is moved to discarded_claims, not left in "findings"
    # (build_report's active/rejected split) -- queue_id's REJECTED verdict won
    # over the fid bundle's CONFIRMED, so the finding lands there, not as an
    # advisor_confirmed entry in report["findings"].
    assert report["findings"] == []
    assert report["discarded_claims"][0]["evidence"]["status"] == "rejected"


def test_bundle_does_not_clobber_own_run_id_or_stage(tmp_path):
    d = tmp_path / "verdicts"; d.mkdir()
    (d / "verdicts-app-SEC.json").write_text(json.dumps({
        "verdicts": [{"finding_id": "SEC-100", "verdict": "CONFIRMED",
                      "run_id": "OWN", "stage": "backup"}],
        "_panopticon": {"run_id": "BUNDLE", "stage": "primary"}}))
    by_fid, _ = evidence.load_verdict_bundles(str(d))
    v = evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid, run_id="OWN")
    assert v["run_id"] == "OWN"      # own run_id preserved
    assert v["stage"] == "backup"    # own stage preserved


def test_non_dict_panopticon_is_tolerated(tmp_path):
    d = tmp_path / "verdicts"; d.mkdir()
    (d / "verdicts-app-SEC.json").write_text(json.dumps(
        {"verdicts": [{"finding_id": "SEC-1", "verdict": "CONFIRMED"}],
         "_panopticon": ["oops"]}))
    by_fid, bad = evidence.load_verdict_bundles(str(d))   # must not raise
    assert "SEC-1" in by_fid


def test_stale_cross_run_backup_does_not_evict_valid_primary(tmp_path):
    _bundle(tmp_path, "verdicts-app-SEC.json",
            [{"finding_id": "SEC-100", "verdict": "CONFIRMED"}], stage="primary", run_id="R")
    d = _bundle(tmp_path, "verdicts-app-SEC-backup.json",
                [{"finding_id": "SEC-100", "verdict": "REJECTED"}], stage="backup", run_id="OLD")
    by_fid, _ = evidence.load_verdict_bundles(d)
    v = evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid, run_id="R")
    assert v is not None and v["verdict"] == "CONFIRMED"    # valid primary survives


def test_load_verdicts_detailed_ignores_bundles(tmp_path):
    d = tmp_path / "verdicts"; d.mkdir()
    (d / "verdicts-app-SEC.json").write_text(json.dumps(
        {"verdicts": [{"finding_id": "SEC-1", "verdict": "CONFIRMED"}],
         "_panopticon": {"run_id": "R", "stage": "primary"}}))
    (d / "junk.json").write_text("not json {")
    verds, unloadable = evidence.load_verdicts_detailed(str(d))
    files = {u["file"] for u in unloadable}
    assert "verdicts-app-SEC.json" not in files   # bundle NOT flagged
    assert "junk.json" in files                   # genuinely-corrupt STILL flagged


def test_valid_bundle_run_has_zero_unloadable(tmp_path):
    import os
    import synthesize
    fp = tmp_path / "findings-app-SEC.json"
    fp.write_text(json.dumps({"findings": [
        {"domain": "SEC", "code": "SEC-A1A", "severity": "HIGH", "title": "t",
         "description": "x", "location": {"file": "a.py", "line_start": 1},
         "category": "authz"}]}))
    findings = synthesize.load_findings([str(fp)])
    fid = findings[0]["id"]
    vd = tmp_path / "verdicts"; vd.mkdir()
    (vd / "verdicts-app-SEC.json").write_text(json.dumps(
        {"verdicts": [{"finding_id": fid, "verdict": "CONFIRMED"}],
         "_panopticon": {"run_id": "R", "role": "domain_advisor",
                         "domain": "SEC", "group": "app", "stage": "primary"}}))
    out = tmp_path / "report.json"
    # Run from an empty cwd (tmp_path), not the real repo root: main() auto-
    # discovers .panopticon/verify-queue.json from the CURRENT directory, and
    # this repo's own .panopticon/ carries a real (stale) run_id that would
    # shadow the "R" run_id used here, rejecting the bundle's verdict on the
    # run_id check for reasons unrelated to what this test is asserting.
    cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        synthesize.main(["--verdicts-dir", str(vd), "--out", str(out), str(fp)])
    finally:
        os.chdir(cwd)
    rep = json.loads(out.read_text())
    assert rep["meta"]["coverage"]["verdicts"]["unloadable"] == 0
    assert rep["findings"][0]["evidence"]["status"] == "advisor_confirmed"


def test_bundle_verdict_counted_in_supplied(tmp_path):
    import synthesize
    fp = tmp_path / "findings-app-SEC.json"
    fp.write_text(json.dumps({"findings": [
        {"domain": "SEC", "code": "SEC-A1A", "severity": "HIGH", "title": "t",
         "description": "x", "location": {"file": "a.py", "line_start": 1},
         "category": "authz"}]}))
    findings = synthesize.load_findings([str(fp)])
    fid = findings[0]["id"]
    d = _bundle(tmp_path, "verdicts-app-SEC.json",
                [{"finding_id": fid, "verdict": "CONFIRMED"}], run_id=None)
    by_fid, _ = evidence.load_verdict_bundles(d)
    report = synthesize.build_report(findings, [], "src", "high",
                                     "2026-08-15T00:00:00Z", verdicts={},
                                     verdict_bundles=by_fid, verdicts_supplied=True)
    vs = report["meta"]["coverage"]["verdicts"]
    assert vs["matched"] == 1 and vs["supplied"] >= 1 and vs["matched"] <= vs["supplied"]
