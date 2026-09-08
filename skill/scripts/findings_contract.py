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

    Domain codes (groups_schema.DOMAINS) are hyphen-free, so the domain is the
    last hyphen-delimited token before `.json`. Shared with `present_cells` so a
    defect diagnostic and a coverage cell are keyed the same way -- naming a
    dropped file without being able to say which cell it belonged to would leave
    the floor audit unable to act on it.
    """
    import os
    base = os.path.basename(str(path))
    if not (base.startswith("findings-") and base.endswith(".json")):
        return None
    stem = base[len("findings-"):-len(".json")]
    if "-" not in stem:
        return None
    group, _, domain = stem.rpartition("-")
    return [group, domain] if group and domain else None
