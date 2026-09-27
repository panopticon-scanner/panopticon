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
    hyphens. A trailing token that is not a domain code names NO cell: such a
    file is still reported BY NAME wherever it was read, but nothing may key a
    cell off it -- claiming one invents a cell the rest of the pipeline cannot
    see.
    """
    base = os.path.basename(str(path))
    if not (base.startswith("findings-") and base.endswith(".json")):
        return None
    stem = base[len("findings-"):-len(".json")]
    group, sep, domain = stem.rpartition("-")
    if not (sep and group and domain in groups_schema.DOMAINS):
        return None
    return [group, domain]
