import json, os
import jsonschema
import pytest

import scripts.phases.persist as persist
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
    assert jsonschema.validate(verdict, schema) is None

def test_verdict_schema_rejects_invalid_input():
    # #run7 TST-A2D: the advisor-verdict schema was only ever validated
    # POSITIVELY. Prove it has teeth -- an out-of-enum verdict and a missing
    # required field must both be REJECTED (else a silent loosening -- widened
    # enum, emptied `required`, additionalProperties flipped -- goes unnoticed).
    schema = _load("advisor-verdict-schema.json")
    base = {
        "finding_id": "SEC-001", "verdict": "CONFIRMED", "confidence": "LIKELY",
        "reasoning": "r", "explored": ["a.py"], "references": ["a.py:1"],
        "citations": {"cwe": [], "owasp": [], "cve": []},
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(dict(base, verdict="MAYBE"), schema)   # out-of-enum
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({k: v for k, v in base.items() if k != "verdict"},
                            schema)                                 # missing required


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


def test_verdict_bundle_inlines_the_advisor_verdict_verbatim():
    # D10 ruling 3: the verify round returns `{"verdicts": [...]}`, and a CLI
    # that takes a constrained-output schema needs ONE file describing that --
    # $ref-free, because the CLIs resolve no external references. Inlined, so
    # the two can drift; this is the test that says they may not. The rule is
    # exact equality with the published advisor verdict minus its own
    # `$schema` keyword (a subschema declares no dialect).
    bundle = _load("verdict-bundle-schema.json")
    advisor = _load("advisor-verdict-schema.json")
    assert bundle["properties"]["verdicts"]["items"] == {
        k: v for k, v in advisor.items() if k != "$schema"}
    assert "$ref" not in json.dumps(bundle)


def test_verdict_bundle_is_the_shape_persist_accepts():
    bundle = _load("verdict-bundle-schema.json")
    assert bundle["title"] == "PanopticonVerdictBundle"
    assert sorted(bundle["required"]) == ["_panopticon", "verdicts"]
    stamp = bundle["properties"]["_panopticon"]["properties"]
    assert {"run_id", "group", "domain", "stage", "stamped_by"} <= set(stamp)
    good = {"verdicts": [{"finding_id": "SEC-001", "verdict": "CONFIRMED",
                          "confidence": "LIKELY", "reasoning": "r",
                          "explored": ["a.py"], "references": ["a.py:1"],
                          "citations": {"cwe": [], "owasp": [], "cve": []}}],
            "_panopticon": {"run_id": "RID", "role": "domain_advisor",
                            "group": "app", "domain": "SEC", "stage": "primary"}}
    assert jsonschema.validate(good, bundle) is None
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"verdicts": []}, bundle)               # no stamp
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(dict(good, verdicts=[{"finding_id": "x"}]), bundle)


def _refs(node):
    """Every `$ref` string anywhere in a loaded schema."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                yield value
            else:
                for ref in _refs(value):
                    yield ref
    elif isinstance(node, list):
        for item in node:
            for ref in _refs(item):
                yield ref


def test_every_published_output_schema_is_self_contained():
    # D10 F9: these three files are handed to a host CLI as the schema its
    # reply must satisfy (`persist.ROLE_SCHEMAS` -> `--json-schema`). The CLI
    # resolves nothing on our behalf and fetches nothing, so a reference OUT of
    # the document -- a sibling file, a URL -- reaches it broken, and the CLI's
    # own answer to a schema it cannot resolve is not ours to predict.
    # INTERNAL refs are allowed and used: the findings envelope's two finding
    # shapes live under `#/definitions`, which every implementation resolves
    # inside the document it was given.
    for name in sorted(set(persist.ROLE_SCHEMAS.values())):
        schema = _load(name)
        for ref in _refs(schema):
            assert ref.startswith("#/definitions/"), (name, ref)


def test_no_published_schema_requires_a_stamp_key_the_driver_cannot_fill():
    # D10 F7: `_controller_stamp` fills the identity keys the ENTRY declares --
    # `persist._STAMP_KEYS`, which the driver wrote onto it -- and nothing
    # else. `role` is the agent's own word for what it was; no entry carries
    # one, so no controller-stamped reply can. A published schema that
    # REQUIRED `role` would make the CLI refuse, at its structured-output gate,
    # precisely the replies `persist.accepts` takes.
    stamped = {"run_id": "RID", "group": "app", "domain": "SEC", "stage": "primary"}
    assert sorted(stamped) == sorted(persist._STAMP_KEYS)       # the whole of what it fills
    for name, body in (("findings-envelope-schema.json", {"findings": []}),
                       ("verdict-bundle-schema.json", {"verdicts": []})):
        schema = _load(name)
        stamp = schema["properties"]["_panopticon"]
        assert set(stamp["required"]) <= set(persist._STAMP_KEYS), (name, stamp["required"])
        body["_panopticon"] = dict(stamped, stamped_by="controller")
        assert jsonschema.validate(body, schema) is None, name


def test_advisor_verdict_schema_carries_the_evidence_scope_fields():
    # #1638 P16 ruling 2: the grant the driver made is RECORDED in the verdict,
    # and a verdict that could not be reached inside it names what it needed.
    # Both OPTIONAL -- a primary-round verdict is granted the whole cell and
    # records neither.
    schema = _load("advisor-verdict-schema.json")
    props = schema["properties"]
    assert set(props["evidence_scope"]["properties"]) == {
        "granted", "cap", "truncated"}
    assert props["evidence_scope"]["properties"]["granted"]["items"]["type"] == "string"
    assert props["evidence_scope"]["properties"]["cap"]["type"] == "integer"
    assert props["evidence_scope"]["properties"]["truncated"]["type"] == "boolean"
    assert props["missing_evidence"]["items"]["type"] == "string"
    assert "evidence_scope" not in schema["required"]
    assert "missing_evidence" not in schema["required"]


def test_a_scope_limited_verdict_validates_against_both_published_schemas():
    verdict = {
        "finding_id": "SEC-001",
        "verdict": "NEEDS_MORE_INFO",
        "confidence": "POSSIBLE",
        "reasoning": "the call sites are outside my granted evidence",
        "explored": ["synth/render.py"],
        "references": ["synth/render.py:12"],
        "citations": {"cwe": [], "owasp": [], "cve": []},
        "evidence_scope": {"granted": ["synth/render.py"], "cap": 12,
                           "truncated": False},
        "missing_evidence": ["synth/grading.py", "synthesize.py"],
    }
    assert jsonschema.validate(verdict, _load("advisor-verdict-schema.json")) is None
    bundle = {"verdicts": [verdict], "_panopticon": {"run_id": "RID"}}
    assert jsonschema.validate(bundle, _load("verdict-bundle-schema.json")) is None


def test_report_schema_knows_the_backup_scope_limited_status():
    # Ruling 3: the new status is a REPORTED state, so the published report
    # schema has to admit it -- in the finding's evidence block and in the
    # evidence_stats counters the dashboard reads.
    schema = _load("report-schema.json")
    ev = (schema["properties"]["findings"]["items"]["properties"]["evidence"]
          ["properties"])
    assert "backup_scope_limited" in ev["status"]["enum"]
    assert ev["missing_evidence"]["items"]["type"] == "string"
    stats = (schema["properties"]["summary"]["properties"]["evidence_stats"]
             ["properties"])
    assert stats["backup_scope_limited"]["type"] == "integer"
