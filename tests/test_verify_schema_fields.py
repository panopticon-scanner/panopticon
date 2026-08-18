import json, os
import jsonschema
REF = os.path.join(os.path.dirname(__file__), os.pardir, "skill", "reference")

def _load(name):
    with open(os.path.join(REF, name), encoding="utf-8") as fh:
        return json.load(fh)

def test_verdict_schema_has_code_and_stage():
    props = _load("advisor-verdict-schema.json")["properties"]
    assert "code" in props
    assert props["stage"]["enum"] == ["primary", "backup"]

def test_verdict_schema_does_not_require_run_id():
    # #1054: run_id was required by the schema but omitted by the advisor prompt
    # example and ignored by the tool-verdict done-predicate -- the tool-advisor
    # path has no run_id to echo (driver writes no verify-queue.json for it). The
    # prompt example is the source of truth; run_id stays an allowed optional
    # property, never required, so a real verdict without it validates.
    schema = _load("advisor-verdict-schema.json")
    assert "run_id" not in schema["required"]
    assert "run_id" in schema["properties"]     # still allowed if a host stamps it

def test_real_advisor_verdict_without_run_id_validates():
    # #1054, the 79/79 scenario: a well-formed verdict shaped exactly like what
    # the advisor prompt asks for (valid enums, no run_id) must pass the schema.
    schema = _load("advisor-verdict-schema.json")
    verdict = {
        "finding_id": "SEC-001",
        "verdict": "CONFIRMED",
        "confidence": "LIKELY",
        "reasoning": "traced the sink to an unsanitized query param",
        "explored": ["app/db.py", "app/routes.py"],
        "references": ["app/db.py:42"],
        "citations": {"cwe": ["CWE-89"], "owasp": ["A03:2021"], "cve": []},
    }
    jsonschema.validate(verdict, schema)   # must not raise

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
