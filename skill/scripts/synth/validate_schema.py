"""The types `report-schema.json` pins: enforcing them, and normalizing to them.

THE PRINCIPLE (#1639 P15 / #1602, fix round 1). **The schema pins the
CONTROLLER's output.** Every input that comes from a review agent or from a
target-writable file is normalized to the pinned types BEFORE it reaches the
report, so a schema error can only ever mean a bug in panopticon itself --
never a lever a reviewed repository or a review agent can pull. That is what
makes it safe for a schema failure to be terminal (`ARTIFACT_INVALID`): the
only writer who can trip it is us. Without it, a reviewer that typed
`"cvss": 7.5` instead of `{"score": 7.5}`, or a target that pre-committed one
malformed file under `.panopticon`, would decide whether a paid-for run
produces a result.

Two halves, deliberately in one module so they cannot disagree about what the
pinned type IS: `schema_errors` validates on the way out, `repair_finding`
normalizes on the way in, and the second derives its rules from the first's
schema file rather than restating them. The boundaries the principle covers:
`repair_finding` (agent and tool findings, via `findings.normalize_finding`),
`integrity.cross_domain_findings` and `plan.audit_floor_cells` (which read
agent payloads and `.panopticon/coverage-*.json` respectively), and
`report.assemble`'s deliberately un-type-pinned `meta.host_capabilities`
subtree, which is copied verbatim from an untrusted artifact and is therefore
described in the schema without being constrained by it.

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
import sys

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


# ---------------------------------------------------------------------------
# The other direction: repairing an INPUT to the types the schema pins.
# ---------------------------------------------------------------------------
# Same module on purpose. One place knows what the report contract pins, and it
# both enforces that contract on the way out and normalizes untrusted input to
# it on the way in -- so the two can never disagree about what the pinned type
# IS. Every rule below is derived from `report-schema.json` itself rather than
# restated here; a vocabulary written down twice is the drift #1602 is about.

_FINDING_ITEM = None


def finding_item_schema():
    """The published `findings[]` item subschema, loaded once.

    Returns {} when the schema cannot be read -- repair then becomes a no-op
    and `schema_errors` is the one that fails closed. Repair must not be the
    thing that raises: it runs on every finding of every run.
    """
    global _FINDING_ITEM
    if _FINDING_ITEM is None:
        try:
            with open(os.path.join(REFERENCE_DIR, REPORT_SCHEMA),
                      encoding="utf-8") as fh:
                doc = json.load(fh)
            _FINDING_ITEM = doc["properties"]["findings"]["items"]
        except (OSError, ValueError, KeyError, TypeError):
            _FINDING_ITEM = {}
    return _FINDING_ITEM


# Fields whose non-conforming value is DROPPED rather than coerced, because the
# coercion would not be lossless -- it would invent a claim. `location.file`
# drives on-diff classification, group attribution and the LoC denominator, so
# `str(7)` there is not a repair, it is a fabricated path. Dropping it makes
# the whole location fall away (findings.normalize_finding's #1522 rule), which
# is the honest answer: the finding is real, its locus was not stated.
_DROP_NEVER_COERCE = ("location.file",)

# Fields a LATER controller stage owns outright, which this pass must leave
# alone: it would drop a value that stage is about to repair better (it knows
# what the field means; this pass only knows its type) or rebuild from scratch.
# Skipping one is a claim that the report cannot carry a bad value for it, so
# each entry says which stage makes that true -- and `test_validate_schema`
# holds the list to the schema, so a new pinned field cannot join it silently.
_OWNED_DOWNSTREAM = {
    "id": "rewritten by evidence.matrix_finding_id after normalization (#1109)",
    "severity": "normalize_finding coerces case-insensitively and falls back to INFO",
    "confidence": "normalize_finding coerces, else derives it from `verdict`",
    "panel": "normalize_finding validates it, else derives it from the domain",
    "title": "normalize_finding rebuilds it from title/description, always a string",
    "short_title": "normalize_finding derives it from the repaired title",
    "evidence": "derive_evidence rebuilds it from a real verdict; agent copies are stripped",
    "fingerprint": "stamped by verdicts.resolve_findings from evidence.finding_fingerprint",
    "delta": "stamped by delta.classify_findings from diff_map.classify",
    "citations": "enrich_citations rebuilds it from validated CWE/OWASP/SSVC/CVE parts",
    "citation_quality": "popped by verdicts.resolve_findings before the report is built",
}


def _conforms(value, node):
    """Does `value` already satisfy this node's pinned type/enum/bound?"""
    if "enum" in node and value not in node["enum"]:
        return False
    if ("minimum" in node and isinstance(value, (int, float))
            and not isinstance(value, bool) and value < node["minimum"]):
        return False               # `line_start: 0` is an integer and still invalid
    types = node.get("type")
    if types is None:
        return True                        # unpinned (or anyOf/$ref): leave alone
    types = types if isinstance(types, list) else [types]
    for t in types:
        if t == "null" and value is None:
            return True
        if t == "boolean" and isinstance(value, bool):
            return True
        if t == "integer" and isinstance(value, int) and not isinstance(value, bool):
            return True
        if t == "number" and isinstance(value, (int, float)) and not isinstance(value, bool):
            return True
        if t == "string" and isinstance(value, str):
            return True
        if t == "array" and isinstance(value, list):
            return True
        if t == "object" and isinstance(value, dict):
            return True
    return False


def _coerce(value, node, path):
    """(ok, value) -- `value` repaired to this node's pinned type, or dropped.

    The repairs are the lossless ones and only those: a numeric string or an
    integral float to an integer, a numeric string to a number, a scalar to the
    string spelling of itself, a lone conforming scalar to the one-element
    array it was meant to be (`"references": "CWE-89"`), and a bare CVSS score
    to the `{score}` object the schema pins. Anything else is dropped, because
    guessing is how a validator becomes a fabricator.
    """
    types = node.get("type")
    types = [] if types is None else (types if isinstance(types, list) else [types])
    if "enum" in node:
        return False, None                 # a value outside the vocabulary is not repairable
    if "integer" in types:
        if isinstance(value, float) and value.is_integer():
            value = int(value)
        elif isinstance(value, str):
            try:
                value = int(value.strip())
            except ValueError:
                return False, None
        if isinstance(value, int) and not isinstance(value, bool):
            if "minimum" in node and value < node["minimum"]:
                return False, None
            return True, value
        return False, None
    if "number" in types and isinstance(value, str):
        try:
            return True, float(value.strip())
        except ValueError:
            return False, None
    if "string" in types and isinstance(value, (int, float)) and not isinstance(value, bool):
        if path in _DROP_NEVER_COERCE:
            return False, None
        return True, str(value)
    if "array" in types and not isinstance(value, list):
        # A single entry written where a list belongs -- keep it if it is the
        # thing the list holds, drop it otherwise.
        items = node.get("items") or {}
        if _conforms(value, items):
            return True, [value]
        return False, None
    if "object" in types and path == "cvss" and not isinstance(value, dict):
        ok, score = _coerce(value, {"type": "number"}, "cvss.score")
        if ok or isinstance(value, (int, float)) and not isinstance(value, bool):
            return True, {"score": float(score if ok else value)}
        return False, None
    return False, None


def _repair_node(value, node, path, changes):
    """(ok, value) for one value against one subschema; recurses into
    described objects and arrays. `changes` collects (path, what) for every
    field this pass repaired or dropped."""
    if not _conforms(value, node):
        ok, repaired = _coerce(value, node, path)
        if not ok:
            changes.append((path, "dropped"))
            return False, None
        changes.append((path, "repaired"))
        value = repaired
    if isinstance(value, dict):
        for key, sub in (node.get("properties") or {}).items():
            if key not in value:
                continue
            ok, repaired = _repair_node(value[key], sub, "%s.%s" % (path, key) if path else key,
                                        changes)
            if ok:
                value[key] = repaired
            else:
                value.pop(key, None)
        required = [k for k in (node.get("required") or []) if k not in value]
        if required:
            return False, None             # e.g. a location whose `file` was dropped
    elif isinstance(value, list) and node.get("items"):
        kept = []
        for entry in value:
            ok, repaired = _repair_node(entry, node["items"], "%s[]" % path, changes)
            if ok:
                kept.append(repaired)
        value = kept
    return True, value


def repair_finding(finding, warn=None):
    """Normalize one finding to the types `report-schema.json` pins.

    THE PRINCIPLE (#1639 P15 / #1602): the schema pins the CONTROLLER's output.
    Every input that comes from an agent or from a target-writable file is
    normalized to the pinned types BEFORE it reaches the report, so a schema
    error can only ever mean a controller bug -- never a lever a review agent
    or a scanned repository can pull. Without this, a reviewer that wrote
    `"cvss": 7.5` instead of `{"score": 7.5}` would end a whole paid-for run in
    `error`, and a target that pre-committed one malformed `.panopticon` file
    could do the same on purpose.

    Repairs in place and returns the finding. EVERY change is announced on
    stderr (or through `warn`) -- repairs included, not only drops: a value
    that did not match the contract is a fact about the reviewer's output, and
    silently swallowing it would trade one silence for another. Never raises --
    it runs on every finding of every run, and a malformed input must not be
    able to crash the pipeline either.
    """
    schema = finding_item_schema()
    if not schema or not isinstance(finding, dict):
        return finding
    changes = []
    for key, sub in (schema.get("properties") or {}).items():
        if key not in finding or key in _OWNED_DOWNSTREAM:
            continue
        ok, repaired = _repair_node(finding[key], sub, key, changes)
        if ok:
            finding[key] = repaired
        else:
            finding.pop(key, None)
    for path, what in changes:
        message = ("findings: %s: %s %s -- it did not match the type "
                   "report-schema.json pins for it"
                   % (finding.get("id") or "?", what, path))
        if warn is not None:
            warn(message)
        else:
            print(message, file=sys.stderr)
    return finding
