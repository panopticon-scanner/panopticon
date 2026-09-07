"""OCRDb code validation and verdict-quality adjustments."""
import sys

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
    fallbacks = {}
    domainless = 0
    mismatch = 0
    for f in findings:
        code = f.get("code")
        if not code:
            continue
        stated, derived = f.get("domain"), ocrdb.domain_of(code)
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

def apply_verdict_quality(findings, matched, bundle):
    """Apply the advisor's code confirm/correct and the severity-override
    discipline; return the counters merged into meta.coverage.ocrdb.

    Deterministic: the advisor PROPOSES (via its matched verdict / the finding's
    severity_override), synthesize APPLIES under fixed rules. Severity is mutated
    only here, only by the disclosed override discipline. `matched` maps
    id(finding) -> the winning verdict (or None) from build_report's match loop.
    """
    code_corrections = 0
    ov_count = ov_up = ov_down = 0
    for f in findings:
        v = matched.get(id(f))
        if v:
            vc = v.get("code")
            if (vc and bundle is not None and ocrdb.validate_code(bundle, vc)
                    and vc != f.get("code")):
                f["code"] = vc
                f["code_corrected_by"] = "agent:advisor"
                code_corrections += 1
            if (str(v.get("stage")) == "backup"
                    and str(v.get("verdict", "")).upper() == "CONFIRMED"):
                f["backup_confirmed"] = True
        ov = f.get("severity_override")
        if isinstance(ov, dict):
            default = ocrdb.default_severity(bundle, f.get("code"))
            if not ov.get("reason"):
                if default:
                    f["severity"] = default
                f.pop("severity_override", None)
                print("synthesize: severity_override without reason on %s dropped; "
                      "reverted to code default %r" % (f.get("id"), default),
                      file=sys.stderr)
            else:
                ov_count += 1
                cur = _SEV_ORDINAL.get(f.get("severity"), 0)
                base = _SEV_ORDINAL.get(default, cur)
                if cur > base:
                    ov_up += 1
                elif cur < base:
                    ov_down += 1
    return {"code_corrections": code_corrections,
            "overrides": {"count": ov_count, "up": ov_up, "down": ov_down}}
