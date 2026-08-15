import ocrdb
import synthesize

def _bundle():
    return {"domains": {"SEC": {"entries": {
        "SEC-A1A": {"name": "n1", "default_severity": "MEDIUM"},
        "SEC-B2B": {"name": "n2", "default_severity": "HIGH"}}}}}

def test_default_severity_lookup():
    b = _bundle()
    assert ocrdb.default_severity(b, "SEC-A1A") == "MEDIUM"
    assert ocrdb.default_severity(b, "SEC-ZZZ") is None
    assert ocrdb.default_severity(None, "SEC-A1A") is None

def test_advisor_corrects_code_with_provenance():
    b = _bundle()
    f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "HIGH", "domain": "SEC"}
    cov = synthesize.apply_verdict_quality(
        [f], {id(f): {"code": "SEC-B2B", "verdict": "CONFIRMED", "stage": "primary"}}, b)
    assert f["code"] == "SEC-B2B"
    assert f["code_corrected_by"] == "agent:advisor"
    assert cov["code_corrections"] == 1

def test_override_missing_reason_reverts_to_code_default():
    b = _bundle()
    f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "CRITICAL", "domain": "SEC",
         "severity_override": {"from": "MEDIUM", "to": "CRITICAL"}}   # no reason
    cov = synthesize.apply_verdict_quality([f], {}, b)
    assert f["severity"] == "MEDIUM"                 # reverted to code default
    assert "severity_override" not in f
    assert cov["overrides"]["count"] == 0

def test_valid_override_kept_and_counted_up():
    b = _bundle()
    f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "CRITICAL", "domain": "SEC",
         "severity_override": {"from": "MEDIUM", "to": "CRITICAL", "reason": "prod exposed"}}
    cov = synthesize.apply_verdict_quality([f], {}, b)
    assert f["severity"] == "CRITICAL"
    assert cov["overrides"] == {"count": 1, "up": 1, "down": 0}

def test_backup_confirm_sets_flag():
    f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "HIGH"}
    synthesize.apply_verdict_quality(
        [f], {id(f): {"verdict": "CONFIRMED", "stage": "backup"}}, _bundle())
    assert f["backup_confirmed"] is True

def test_build_report_counts_land_in_ocrdb_coverage(tmp_path):
    import json
    fp = tmp_path / "findings-app-SEC.json"
    fp.write_text(json.dumps({"findings": [
        {"domain": "SEC", "code": "SEC-A1A", "severity": "CRITICAL",
         "title": "t", "description": "x",
         "location": {"file": "a.py", "line_start": 1}, "category": "authz",
         "severity_override": {"from": "MEDIUM", "to": "CRITICAL", "reason": "prod"}}]}))
    findings = synthesize.load_findings([str(fp)])
    report = synthesize.build_report(findings, [], "src", None,
                                     "2026-08-15T00:00:00Z")
    ocrdb_cov = report["meta"]["coverage"]["ocrdb"]
    assert ocrdb_cov["overrides"]["count"] == 1
    assert "code_corrections" in ocrdb_cov
