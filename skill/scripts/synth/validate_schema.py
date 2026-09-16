"""Validate an artifact against the JSON Schema panopticon publishes for it.

#1639 P15. `report.validate_report` hand-checked a selected list of fields --
top-level keys, finding ids/severities/panels, the CVSS-and-exploit rule for
security HIGH+ -- and never once loaded `skill/reference/report-schema.json`.
The two contracts therefore disagreed in the only direction that matters:
run-13's independent audit had to run its own Draft 7 validation to establish
that the report was valid, and Codex's repro built a report whose `meta`,
`summary` and `cross_panel` were all `null` and got no production error or
warning at all, while schema validation rejects all three. A published contract
that only a controller-side check enforces is a contract the normal completion
path does not have.

So the schema is loaded here, and it is loaded FAIL-CLOSED. An absent
`jsonschema`, an unreadable schema file or an unparseable one each return an
error rather than an empty list: "we could not check" and "we checked and it
passed" must never render as the same answer, which is exactly what a silent
`except ImportError: return []` would do. `jsonschema` is a declared runtime
dependency (`pyproject.toml`), so the import failing is a broken install, not
a supported mode.

This does NOT replace the hand checks. The schema expresses shape; it cannot
express "a security HIGH from an agent needs a CVSS score and an exploit
scenario", or "no two findings may share an id". Both run, and their errors
are one list (`report.validate_report`).

`driver._scout_shape_errors` still hand-rolls a dependency-free subset on
purpose -- it validates an AGENT's scout profile at a point where a missing
third-party package must not stop a run -- and is deliberately left alone.
"""
import json
import os

# skill/reference/, from skill/scripts/synth/: the shipped contracts every
# artifact is validated against.
REFERENCE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "reference")

REPORT_SCHEMA = "report-schema.json"
X0X_SCHEMA = "x0x-report-schema.json"

# synthesize's exit status for "this run wrote an artifact that does not
# satisfy its own published schema" (#1639 P15 ruling 2). Terminal completion,
# artifact validity and coverage certification are three different facts, and
# each gets its own channel: 1/2 are the GATE's verdicts (FAIL / INCONCLUSIVE,
# both of them valid reports about a coverage question), 3 is a corrupt OCRDb
# bundle, and this is the artifact itself being unreadable as what it claims to
# be. A consumer that sees 4 should not read the report at all.
ARTIFACT_INVALID = 4


def schema_errors(document, schema=REPORT_SCHEMA, schema_path=None):
    """Every way `document` fails its published schema, as error strings.

    `schema` names a file under `skill/reference/`; `schema_path` overrides the
    whole resolution (tests, and any future caller holding a schema elsewhere).
    Each error reads `schema: <json path>: <message>` so it sits alongside
    `validate_report`'s hand checks in one list and still says where it fired.

    Returns [] only when validation actually ran and found nothing.
    """
    path = schema_path or os.path.join(REFERENCE_DIR, schema)
    try:
        import jsonschema
    except ImportError:
        # Fail closed: a report that could not be validated is not a report
        # that passed. jsonschema is a declared runtime dependency.
        return ["schema: jsonschema not installed — report schema not validated"]
    try:
        with open(path, encoding="utf-8") as fh:
            document_schema = json.load(fh)
    except (OSError, ValueError) as exc:
        return ["schema: %s unreadable (%s) — report schema not validated"
                % (os.path.basename(path), exc)]
    validator = jsonschema.Draft7Validator(document_schema)
    # Sorted by json path so two runs over the same bad artifact print the same
    # list in the same order -- iter_errors' own order is unspecified, and this
    # text ends up in a report field and in stderr a human diffs.
    errors = sorted(validator.iter_errors(document),
                    key=lambda e: (e.json_path, e.message))
    return ["schema: %s: %s" % (e.json_path, e.message) for e in errors]
