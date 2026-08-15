import json, os
REF = os.path.join(os.path.dirname(__file__), os.pardir, "skill", "reference")

def _load(name):
    with open(os.path.join(REF, name), encoding="utf-8") as fh:
        return json.load(fh)

def test_verdict_schema_has_code_and_stage():
    props = _load("advisor-verdict-schema.json")["properties"]
    assert "code" in props
    assert props["stage"]["enum"] == ["primary", "backup"]

def test_report_finding_has_override_and_correction_fields():
    fprops = _load("report-schema.json")["properties"]["findings"]["items"]["properties"]
    assert set(fprops["severity_override"]["properties"]) == {"from", "to", "reason"}
    assert fprops["code_corrected_by"]["type"] == "string"
    assert fprops["backup_confirmed"]["type"] == "boolean"

def test_report_ocrdb_coverage_has_override_counters():
    ocrdb = (_load("report-schema.json")["properties"]["meta"]["properties"]
             ["coverage"]["properties"]["ocrdb"]["properties"])
    assert set(ocrdb["overrides"]["properties"]) == {"count", "up", "down"}
    assert ocrdb["code_corrections"]["type"] == "integer"
