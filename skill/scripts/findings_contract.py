"""The runtime acceptance rule for an agent-authored findings file.

#1513 (Codex BR-03): a correctly stamped cell whose `findings` list held only
`null` was accepted by the driver as a COMPLETED review, and synthesis turned it
into `findings: []`, `schema_errors: 0`, certified PASS. A reviewer that returned
garbage was indistinguishable from one that found nothing.

Three separate shallow checks made that possible -- the driver's completion
predicate, resume's done-predicate, and direct synthesis -- and each verified
only that `findings` was a list. Fixing one leaves the others able to certify
invalid input, so the rule lives here and all three call it.

Deliberately shape-only. This is the ADMISSION check: is this payload the thing
the contract says a reviewer writes? Whether a given finding is *good* (severity
vocabulary, citations, location) is normalization's job downstream, and pulling
that in here would make a reviewer's judgement call look like a protocol
violation.

The module owns a second contract, for the same reason: `cell_of` is the one
parse of the `findings-<group>-<domain>.json` NAME (ARC-3899903550, #1765). Four
readers each had their own and disagreed, so a file's cell identity -- not its
payload shape -- is settled here too.

A third, for the same reason (#2104): `schema_version_defect` is the one rule
for the format version an agent-authored findings envelope, verdict bundle or
tool verdict declares. Every admission boundary and every synthesis reader of
those records calls it. It sits BESIDE the run/cell identity checks, never
inside them.
"""
from typing import TYPE_CHECKING
import os

# The domain roster `cell_of` validates a name's trailing token against. Dual
# import convention (#742): this module sits in the flat `skill/scripts`
# namespace beside `plan_contract`, which carries the same fallback, so both
# `scripts.findings_contract` and a bare `import findings_contract` resolve it.
# The edge adds no cycle -- `groups_schema` imports nothing from this tree.
if TYPE_CHECKING:
    from scripts import groups_schema
else:
    try:
        from scripts import groups_schema
    except ModuleNotFoundError:   # imported flat, with skill/scripts on sys.path
        import groups_schema


# #2104: the one format version agent records are written in. ABSENT reads as
# this version: verify and tool replies carry none today (their prompts ask for
# none, and Codex's generation schemas leave no room for one), and old run folders
# are versionless too. That window stays open through 5.x and closes only by
# ruling (#3482). A PRESENT version must be exactly this int, by type as well as
# by value (`synth/delta.py`'s #2382 rule): `True` and `1.0` compare equal to it
# and are not versions. The reason is fixed text and never echoes the value.
SCHEMA_VERSION = 1
UNSUPPORTED_SCHEMA_VERSION = "unsupported schema_version"


def schema_version_defect(record):
    """None when `record` declares no `schema_version` or exactly SCHEMA_VERSION;
    otherwise UNSUPPORTED_SCHEMA_VERSION. A non-object declares nothing."""
    if not isinstance(record, dict) or "schema_version" not in record:
        return None
    version = record["schema_version"]
    if type(version) is int and version == SCHEMA_VERSION:
        return None
    return UNSUPPORTED_SCHEMA_VERSION


def bundle_version_defect(bundle, verdicts):
    """The bundle's own version, then each of `verdicts`: what ADMISSION refuses whole.

    `verdicts` is the bundle's list as the caller already read it through
    `evidence._agent_verdict`, the one door for agent verdicts
    (tests/test_agent_verdict_guard.py). At receipt and in the done predicates,
    one unknown verdict version refuses the whole reply, so the retry runs. Only
    synthesis (`evidence.load_verdict_bundles`) confines a per-verdict one to
    that entry. That is deliberate: don't make one match the other."""
    return schema_version_defect(bundle) or next(
        (UNSUPPORTED_SCHEMA_VERSION for v in verdicts if schema_version_defect(v)), None)


def payload_defects(data):
    """Contract violations in a parsed findings payload; [] means acceptable.

    Each defect is ``{"index": int|None, "reason": str}``. `index` is the
    offending position in `findings`, or None when the payload itself is wrong
    shape. Every bad element is reported, not just the first: "mixed
    valid/invalid" must not read as wholly completed, and the report has to be
    able to say which entries were dropped.
    """
    if not isinstance(data, dict):
        return [{"index": None,
                 "reason": "payload is %s, not a JSON object" % type(data).__name__}]
    if schema_version_defect(data):
        return [{"index": None, "reason": UNSUPPORTED_SCHEMA_VERSION}]
    findings = data.get("findings")
    if not isinstance(findings, list):
        return [{"index": None,
                 "reason": "findings is %s, not a list" % type(findings).__name__}]
    return [{"index": i,
             "reason": "finding %d is %s, not an object" % (i, type(f).__name__)}
            for i, f in enumerate(findings) if not isinstance(f, dict)]


def is_acceptable(data):
    """True when `data` satisfies the findings contract."""
    return not payload_defects(data)


def cell_of(path):
    """``[group, domain]`` for a `findings-<group>-<domain>.json` path, else None.

    THE cell-identity parser. `synth.coverage_io.present_cells`,
    `synth.integrity._expected_from_filename`, `synth.plan.out_of_scope_findings`
    and the ingest's `_group` stamp all call it, so a coverage cell, the mislabel
    guard, a scope lane, a finding's group and a defect diagnostic are keyed the
    same way. Four independent parses used to answer this one question and they
    disagreed at the edges (ARC-3899903550, #1765): an off-roster or mistyped
    domain made ingest stamp no group, told the mislabel guard nothing was wrong
    and hid the cell from the floor audit -- while this function still named a
    cell for it. Every branch failed toward invisible, in four directions.

    Domain codes (`groups_schema.DOMAINS`) are hyphen-free, so the domain is the
    last hyphen-delimited token before `.json` and a group name may contain
    hyphens. A trailing token that is not a domain code names NO cell: claiming
    one invents a cell the rest of the pipeline cannot see. Such a file whose
    PAYLOAD was rejected is still named, now without a cell
    (`malformed_findings_files`); one that parses cleanly is surfaced by
    `unexpected_findings_files` wherever a dispatch plan exists.
    """
    base = os.path.basename(str(path))
    if not (base.startswith("findings-") and base.endswith(".json")):
        return None
    stem = base[len("findings-"):-len(".json")]
    group, sep, domain = stem.rpartition("-")
    if not (sep and group and domain in groups_schema.DOMAINS):
        return None
    return [group, domain]
