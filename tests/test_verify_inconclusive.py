import json
import synthesize as syn

def _cell_file(tmp_path, group, domain, sev, line=1, verdict=None):
    fp = tmp_path / ("findings-%s-%s.json" % (group, domain))
    fp.write_text(json.dumps({"findings": [
        {"domain": domain, "code": "%s-A1A" % domain, "severity": sev, "title": "t",
         "description": "x", "location": {"file": "a.py", "line_start": line},
         "category": "authz"}]}))
    return str(fp)

def test_engaged_matrix_cells_uses_fp():
    f_hi = {"_group": "app", "domain": "SEC", "severity": "HIGH", "title": "t",
            "category": "x", "location": {"file": "a.py", "line_start": 1}}
    f_lo = {"_group": "app", "domain": "QAL", "severity": "LOW", "title": "t",
            "category": "x", "location": {"file": "a.py", "line_start": 2}}
    cells = syn.engaged_matrix_cells([f_hi, f_lo])
    assert ("app", "SEC") in cells and ("app", "QAL") not in cells

def test_below_gate_cell_does_not_force_inconclusive(tmp_path):
    fp = _cell_file(tmp_path, "app", "QAL", "LOW")   # score 0 < F_p, no advisor owed
    findings = syn.load_findings([fp])
    report = syn.build_report(findings, [], "src", "high", "2026-08-15T00:00:00Z",
                              verdicts_supplied=True)
    assert report["summary"]["gate"] != "INCONCLUSIVE"

def test_engaged_unverified_cell_forces_inconclusive(tmp_path):
    fp = _cell_file(tmp_path, "app", "SEC", "HIGH")  # score >= F_p, no verdict
    findings = syn.load_findings([fp])
    report = syn.build_report(findings, [], "src", "high", "2026-08-15T00:00:00Z",
                              verdicts_supplied=True)
    assert report["summary"]["gate"] == "INCONCLUSIVE"
    assert report["meta"]["coverage"]["verify_matrix"]["unverified_engaged"] \
        == [["app", "SEC"]]
