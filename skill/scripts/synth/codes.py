"""OCRDb code validation and verdict-quality adjustments."""
import sys

import scripts.evidence as evidence_mod
import scripts.ocrdb as ocrdb
from . import findings as findings_mod


def validate_finding_codes(findings, bundle):
    """Validate each finding's `code` against the OCRDb bundle. Returns the
    coverage dict {invalid_codes, fallbacks, domainless, code_domain_mismatch}
    or None when no bundle is vendored.

    - a real code: kept, not counted.
    - an explicit '<DOM>-X0X' fallback (or a code the reviewer couldn't match):
      counted per-domain at `fallbacks` (the catalog-gap signal).
    - an unknown, domain-derivable code: replaced with the domain fallback and
      counted at `invalid_codes`.
    - an unknown code with NO derivable domain: normalized to the reserved
      `ZZZ-X0X` sentinel and counted at `domainless` (#1034/#2) — still counted
      at `invalid_codes` too, so that total stays "codes that weren't real".
    - a finding whose stated `domain` disagrees with its code's prefix is
      counted at `code_domain_mismatch` (disclosure only, #1034/#3).
    A finding with no `code` is left alone.
    """
    if bundle is None:
        return None
    invalid = 0
    fallbacks: dict[str, int] = {}
    domainless = 0
    mismatch = 0
    for f in findings:
        code = f.get("code")
        if not code:
            continue
        stated, derived = f.get("domain"), ocrdb.domain_of(code)
        if derived is not None and not ocrdb.is_domain(derived):
            # #1639 P15 F1: a code prefix is what the agent CLAIMS, not a
            # domain. `CWE-798` (the CWE id typed into the OCRDb code field --
            # the most plausible slip there is) claimed `CWE`, which reached
            # `candidates[].domain` in the X0X artifact, where the 11-domain
            # roster is an ENUM: a valid-looking string ended the whole run in
            # `error`, and silently, because the string conforms to
            # report-schema.json. Off-roster is domainless, which the ZZZ
            # sentinel already means; say so rather than repair in silence.
            print("synthesize: %s: code %r names no OCRDb domain (%r); filing it "
                  "under the %s catalog-gap sentinel"
                  % (f.get("id") or "?", code, derived,
                     ocrdb.UNKNOWN_DOMAIN_FALLBACK), file=sys.stderr)
            derived = None
        if stated and derived and stated != derived:
            mismatch += 1                      # #1034/#3: disclose, don't rewrite
        domain = stated or derived
        if ocrdb.validate_code(bundle, code):
            continue
        if domain and code == ocrdb.domain_fallback(domain):
            fallbacks[domain] = fallbacks.get(domain, 0) + 1
        else:
            invalid += 1
            if domain:
                f["code"] = ocrdb.domain_fallback(domain)
                fallbacks[domain] = fallbacks.get(domain, 0) + 1
            else:                              # #1034/#2: no derivable domain
                domainless += 1
                f["code"] = ocrdb.UNKNOWN_DOMAIN_FALLBACK
    return {"invalid_codes": invalid, "fallbacks": fallbacks,
            "domainless": domainless, "code_domain_mismatch": mismatch}

# #run7 QAL-D1B: derive the ascending severity ordinal from the shared
# evidence.SEV_ORDER (descending) rather than re-encoding it as a hand-literal --
# a reorder/add/remove there now stays in sync automatically instead of silently
# desyncing meta.coverage.ocrdb.overrides.
_SEV_ORDINAL = {s: i for i, s in enumerate(reversed(findings_mod.SEV_ORDER))}

# OCRDb 0.7's controlled, consumer-side reasons. A reason uses
# ``<modifier>: <instance fact>`` so prose that merely mentions a modifier does
# not acquire its below-floor exception.
_SEVERITY_MODIFIERS = frozenset({
    "test-or-fixture-scope",
    "operator-controlled-input",
    "local-or-offline-context",
    "regenerable-or-recoverable-data",
    "dev-or-ci-tooling",
    "intentionally-public-value",
    "documented-accepted-risk",
    "compensating-control-present",
})


def _has_severity_modifier(reason):
    if not isinstance(reason, str) or ":" not in reason:
        return False
    modifier, fact = reason.split(":", 1)
    return modifier.strip() in _SEVERITY_MODIFIERS and bool(fact.strip())


def _cited_rung_target(bounds, rung_name, citation):
    """Highest named rung target, cited by label or exact condition text."""
    if not isinstance(citation, str):
        return None
    targets = []
    rungs = bounds.get(rung_name)
    if not isinstance(rungs, list):
        return None
    for index, rung in enumerate(rungs):
        if not isinstance(rung, dict):
            continue
        if citation not in ("%s[%d]" % (rung_name, index), rung.get("condition")):
            continue
        target = rung.get("to")
        if target in _SEV_ORDINAL:
            targets.append(target)
    return max(targets, key=lambda severity: _SEV_ORDINAL[severity]) if targets else None


def _clamp_to_range(default, requested, override, bounds):
    """Return the deterministic 0.7 range/rung-constrained severity."""
    base = _SEV_ORDINAL.get(default)
    current = _SEV_ORDINAL.get(requested)
    floor = _SEV_ORDINAL.get(bounds.get("floor"))
    ceiling = _SEV_ORDINAL.get(bounds.get("ceiling"))
    if base is None or current is None or floor is None or ceiling is None:
        return requested

    allowed = current
    if current > base:
        cited = _cited_rung_target(bounds, "raise_when", override.get("rung"))
        cited_ordinal = _SEV_ORDINAL[cited] if cited is not None else base
        allowed = min(current, ceiling, max(base, cited_ordinal))
    elif current < base and not _has_severity_modifier(override.get("reason")):
        cited = _cited_rung_target(bounds, "lower_when", override.get("rung"))
        cited_ordinal = _SEV_ORDINAL[cited] if cited is not None else base
        allowed = max(current, floor, cited_ordinal)

    by_ordinal = {ordinal: severity for severity, ordinal in _SEV_ORDINAL.items()}
    return by_ordinal[allowed]


def severity_after_discipline(finding, bundle):
    """The severity `apply_verdict_quality` leaves on `finding`, without changing it.

    #3727: this is decided by the finding's own content and the catalog, never by a
    verdict, so it is known before findings at one line are merged. The merge ranks
    by it (`corroborate.merge_rank`): ranked by the severity a reviewer CLAIMED, a
    claim at CRITICAL with an empty `severity_override` won the merge over another
    cell's confirmed CRITICAL and was then reset to its code's LOW default here.
    `apply_verdict_quality` applies exactly this value, so the two cannot disagree."""
    disciplined = _within_range(finding, bundle)
    ceiling = _ceiling(finding, bundle)
    if ceiling and _SEV_ORDINAL.get(disciplined, -1) > _SEV_ORDINAL[ceiling[1]]:
        return ceiling[1]
    return disciplined


def _within_range(finding, bundle):
    """The default/override/range discipline alone (#3330), before the ceiling."""
    severity = finding.get("severity")
    override = finding.get("severity_override")
    default = ocrdb.default_severity(bundle, finding.get("code"))
    bounds = ocrdb.severity_range(bundle, finding.get("code"))
    ranged = bool(default and bounds and not evidence_mod.is_tool_sourced(finding))
    if not isinstance(override, dict):
        # #3330 r1 F1: an agent could omit the override object altogether and bypass
        # every reason/rung check. Tool severities are an independent scanner/CVSS
        # axis and must remain untouched.
        return default if ranged else severity
    if not override.get("reason"):
        return default or severity
    return _clamp_to_range(default, severity, override, bounds) if ranged else severity


def _ceiling(finding, bundle):
    """#3754: `(domain, ceiling)` bounding this agent finding, or None. Only a code
    the catalog knows decides it, never the cell that wrote the claim up: with
    `--fail-on critical`, the default, a clamp from CRITICAL to HIGH turns a FAIL
    into a PASS, and a real defect an OPS or TST cell filed without a code must not
    be silenced by which cell found it (`outside_range` flags that one instead)."""
    if evidence_mod.is_tool_sourced(finding):
        return None
    return ocrdb.domain_ceiling(bundle, finding.get("code"))


def outside_range(finding, bundle):
    """#3754: `{domain, ceiling}` for an agent claim with no code the catalog knows,
    filed by a cell of a ceilinged domain, at a severity above that ceiling; else
    None. Nothing is changed: the claim keeps its severity and the report says it
    is outside the range."""
    if evidence_mod.is_tool_sourced(finding) or _ceiling(finding, bundle) is not None:
        return None
    if ocrdb.default_severity(bundle, finding.get("code")) is not None:
        return None                        # a known code outside the four domains
    domain = finding.get(evidence_mod.CELL_DOMAIN_FIELD)
    ceiling = ocrdb.DOMAIN_CEILINGS.get(domain) if isinstance(domain, str) else None
    if ceiling and _SEV_ORDINAL.get(finding.get("severity"), -1) > _SEV_ORDINAL[ceiling]:
        return {"domain": domain, "ceiling": ceiling}
    return None


def apply_verdict_quality(findings, matched, bundle):
    """Apply the backup-corroboration flag and the severity-override discipline;
    return the counters merged into meta.coverage.ocrdb.

    Deterministic: the advisor PROPOSES (via its matched verdict / the finding's
    severity_override), synthesize APPLIES under fixed rules. SEVERITY is the
    only axis this function mutates, and only by the disclosed override
    discipline. The advisor's own OCRDb `code` is not applied, here or anywhere:
    `evidence.apply_verdict` records a differing one at `provenance.advisor_code`
    as a considered second opinion about the catalog, and that record is the
    whole of it (#2101 -- this step used to apply it LATER in the live call
    order, overwriting the very code the record was about, so each step read
    correctly alone). The `code` read below is the FINDING's own, for its catalog
    default severity. `matched` maps id(finding) -> the winning verdict (or None)
    from build_report's match loop.
    """
    ov_count = ov_up = ov_down = ov_clamped = ov_missing = 0
    for f in findings:
        v = matched.get(id(f))
        if v:
            if (str(v.get("stage")) == "backup"
                    and str(v.get("verdict", "")).upper() == "CONFIRMED"):
                f["backup_confirmed"] = True
            elif evidence_mod.carried_paths(v):
                # #1638 P16: the backup did not corroborate -- it could not
                # look. Stated as FALSE rather than left absent, because the
                # absent case ("no backup was summoned") is a different fact.
                f["backup_confirmed"] = False
        _record_assessment(f, v)
        ov = f.get("severity_override")
        default = ocrdb.default_severity(bundle, f.get("code"))
        # The one decision (#3727); what follows applies and discloses it.
        requested, applied = f.get("severity"), severity_after_discipline(f, bundle)
        # #3754: say so when the domain's ceiling is what lowered it.
        within, ceiling = _within_range(f, bundle), _ceiling(f, bundle)
        if ceiling and within != applied:
            f["severity_ceiling"] = {"from": within, "domain": ceiling[0],
                                     "ceiling": ceiling[1]}
            print("synthesize: %s: %s %s above the %s ceiling, published %s"
                  % (f.get("id") or "?", f.get("code"), f["severity_ceiling"]["from"],
                     ceiling[0], ceiling[1]), file=sys.stderr)
        flagged = outside_range(f, bundle)
        if flagged:
            f["severity_outside_range"] = flagged
        if not isinstance(ov, dict):
            if applied != requested:
                f["severity"] = applied
            if within != requested:
                ov_missing += 1
                print("synthesize: %s: agent severity %s without severity_override "
                      "reverted to OCRDb %s default %s"
                      % (f.get("id") or "?", requested, f.get("code") or "?",
                         default), file=sys.stderr)
            continue
        if not ov.get("reason"):
            if applied != requested:
                f["severity"] = applied
            f.pop("severity_override", None)
            print("synthesize: severity_override without reason on %s dropped; "
                  "reverted to code default %r" % (f.get("id"), default),
                  file=sys.stderr)
        else:
            ov_count += 1
            if applied != requested:
                ov_clamped += 1
                f["severity"] = applied
                ov["to"] = applied
                print("synthesize: %s: severity override %s clamped to %s "
                      "by OCRDb %s %s"
                      % (f.get("id") or "?", requested, applied, f.get("code") or "?",
                         "severity_range" if within != requested
                         else "domain ceiling (#3754)"), file=sys.stderr)
            cur = _SEV_ORDINAL.get(f.get("severity"), 0)
            base = _SEV_ORDINAL.get(default, cur)
            if cur > base:
                ov_up += 1
            elif cur < base:
                ov_down += 1
    return {"overrides": {"count": ov_count, "up": ov_up, "down": ov_down,
                          "clamped": ov_clamped, "missing": ov_missing}}


def ceiling_ids(findings):
    """#3754: `({domain: [ids]}, [ids])` for `meta.severity_ceiling` and
    `meta.severity_outside_range`: the findings the domain ceiling lowered, and the
    uncoded ones rated above their cell's ceiling. Empty when there are none."""
    lowered: dict = {}
    outside = []
    for f in findings:
        record = f.get("severity_ceiling")
        if isinstance(record, dict) and isinstance(record.get("domain"), str) and f.get("id"):
            lowered.setdefault(record["domain"], []).append(f["id"])
        if isinstance(f.get("severity_outside_range"), dict) and f.get("id"):
            outside.append(f["id"])
    return {k: sorted(v) for k, v in sorted(lowered.items())}, sorted(outside)


def _record_assessment(finding, verdict):
    """#3754, record-only in 5.5: the domain advisor's view of an agent claim's
    severity, beside the finding. Nothing reads it to decide anything."""
    assessed = evidence_mod.severity_assessed(verdict)
    if assessed and not evidence_mod.is_tool_sourced(finding):
        finding["severity_assessed"] = assessed
