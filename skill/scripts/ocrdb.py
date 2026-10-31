"""Read access to the vendored OCRDb domain catalog — the 5.0 review-matrix
finding-code source. Pure: loads the pinned bundle and answers domain-menu /
code-validation queries. Tolerant degrade-to-None when the bundle is absent (the
review then runs code-less = 4.x behavior); a present bundle whose top-level
STRUCTURE is malformed (not a dict / missing the 'domains' map) is a LOUD
ValueError, never a silent no-code run. Individual malformed sub-entries (a
non-dict domain or code entry) degrade gracefully -- they are skipped, so one
corrupt entry can't kill a whole review (see #run7 ARC-F2D). Mirrors
citations.load_cwe_catalog.
See docs/superpowers/specs/2026-08-15-panopticon-5.0-review-matrix-design.md §4.
"""
from typing import Any, TYPE_CHECKING
import json
import os
import re

if TYPE_CHECKING:
    from scripts import _version
else:
    try:
        from scripts import _version
    except ModuleNotFoundError:  # imported flat, with skill/scripts itself on sys.path
        import _version

BUNDLE_VERSION = "0.6.0"
_BUNDLE_NAME = "ocrdb-%s.json" % BUNDLE_VERSION

# The 10 OCRDb domains -> the legacy 6-panel axis (evidence.PANELS), so a
# domain-scoped finding still segments in the panel-graded report (Task 2 uses
# this to back-fill `panel`). Domains with no legacy equivalent bucket to "code".
DOMAIN_TO_PANEL = {
    "SEC": "security", "COD": "code", "ARC": "architecture",
    "TST": "test", "DAT": "database",
    "QAL": "code", "AGT": "code", "OPS": "code", "ACC": "code", "LNG": "code",
    # #1034: the reserved "no derivable domain" sentinel (UNKNOWN_DOMAIN_FALLBACK)
    # buckets to the code panel so a normalized domainless finding still segments.
    "ZZZ": "code",
}

# #1034: a finding whose code yields no derivable domain is normalized to this
# reserved sentinel (canonical, greppable, and — ZZZ being no real domain —
# unmistakably not a catalog code) instead of shipping the raw string.
UNKNOWN_DOMAIN_FALLBACK = "ZZZ-X0X"

# #1034: severity used for a bundle entry that omits default_severity. None in
# the pinned 0.6.0 bundle omit it, so this is latent — but any future entry that
# does gets this assumed level plus a `severity_assumed` flag, never a silent
# fabrication.
_MENU_SEVERITY_WHEN_ABSENT = "MEDIUM"


def _bundle_path():
    return _version.reference_path(_BUNDLE_NAME)


DEFAULT_BUNDLE_PATH = _bundle_path()


def load_bundle(path=None):
    """The parsed OCRDb bundle dict, or None if the vendored file is absent.
    A present-but-malformed bundle raises ValueError (loud)."""
    path = path or DEFAULT_BUNDLE_PATH
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)   # corrupt JSON -> JSONDecodeError (a ValueError)
    if not (isinstance(data, dict) and isinstance(data.get("domains"), dict)):
        raise ValueError("OCRDb bundle %s malformed: missing 'domains' map" % path)
    return data


def _safe_get_dict(mapping, key):
    if not isinstance(mapping, dict):
        return {}
    val = mapping.get(key)
    return val if isinstance(val, dict) else {}


def _entries_for(bundle, domain):
    """The `entries` map for one domain -- {} for a None/non-dict bundle or a
    missing/malformed domain. #run7 QAL-D1A: single-sources the three-step
    domains->domain->entries unwrap that was copy-pasted verbatim across
    domain_menu/domain_criteria/validate_code/default_severity."""
    doms = _safe_get_dict(bundle, "domains")
    dom = _safe_get_dict(doms, domain)
    return _safe_get_dict(dom, "entries")


def domain_outline(bundle, domain):
    """The optional 0.7 domain/area/category routing guide hierarchy.

    ``None`` means the bundle predates guides (including the shipped 0.6
    bundle), which lets the prompt renderer retain its legacy byte-for-byte
    menu. Malformed guide nodes are skipped rather than taking a review down,
    matching the per-entry tolerance of :func:`domain_menu`.
    """
    domains = _safe_get_dict(bundle, "domains")
    dom = _safe_get_dict(domains, domain)
    domain_guide = dom.get("guide")
    areas = _safe_get_dict(dom, "areas")
    domain_guide_text = domain_guide if isinstance(domain_guide, str) else ""
    has_guide = bool(domain_guide_text)
    if not has_guide:
        has_guide = any(
            isinstance(area, dict)
            and ((isinstance(area.get("guide"), str) and bool(area.get("guide")))
                 or any(isinstance(value, str) and bool(value)
                        for value in _safe_get_dict(area, "category_guides").values()))
            for area in areas.values()
        )
    if not has_guide:
        return None

    outline: dict[str, Any] = {"guide": domain_guide_text, "areas": []}
    for area_key in sorted(areas):
        area = areas[area_key]
        if not isinstance(area, dict):
            continue
        categories = _safe_get_dict(area, "categories")
        category_guides = _safe_get_dict(area, "category_guides")
        category_rows = []
        for category_key in sorted(
                categories, key=lambda key: (not str(key).isdigit(),
                                             int(key) if str(key).isdigit() else str(key))):
            category_rows.append({
                "key": str(category_key),
                "name": str(categories[category_key] or ""),
                "guide": (category_guides.get(category_key)
                          if isinstance(category_guides.get(category_key), str) else ""),
            })
        outline["areas"].append({
            "key": str(area_key),
            "name": str(area.get("name") or ""),
            "guide": area.get("guide") if isinstance(area.get("guide"), str) else "",
            "categories": category_rows,
        })
    return outline


def severity_range(bundle, code):
    """A code's optional 0.7 ``severity_range`` object, else ``None``.

    The floor and ceiling are the minimum shape needed by a consumer. Rungs
    remain verbatim so their conditions can be rendered and cited exactly.
    """
    domain = domain_of(code) if isinstance(code, str) else None
    entry = _safe_get_dict(_entries_for(bundle, domain), code) if domain else {}
    value = entry.get("severity_range")
    if not isinstance(value, dict):
        return None
    if not (isinstance(value.get("floor"), str)
            and isinstance(value.get("ceiling"), str)):
        return None
    return value


def _guide_field(value):
    """One TSV field: deterministic, single-line, and tab-free."""
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _guide_name(value):
    """Turn OCRDb's source slugs into compact display names."""
    return _guide_field(str(value or "").replace("-", " ").replace("_", " ")).capitalize()


def _guide_row(*fields):
    return "\t".join(_guide_field(field) for field in fields)


def _guide_groups(menu, outline):
    """Assign codes to their longest area/category prefix."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    assigned: set[str] = set()
    for item in menu:
        code = item["code"]
        suffix = code.split("-", 1)[1] if "-" in code else ""
        choices = []
        for area in outline["areas"]:
            area_key = area["key"]
            if not suffix.startswith(area_key):
                continue
            tail = suffix[len(area_key):]
            for category in area["categories"]:
                category_key = category["key"]
                if tail.startswith(category_key):
                    choices.append((len(category_key), area_key, category_key))
        if choices:
            _, area_key, category_key = max(choices)
            groups.setdefault((area_key, category_key), []).append(item)
            assigned.add(code)
    return groups, assigned


def _guide_code_row(bundle, domain, item):
    code = item["code"]
    bounds = severity_range(bundle, code)
    compact_range = item["severity"]
    if bounds:
        compact_range += " (%s-%s)" % (bounds["floor"], bounds["ceiling"])
    entry = _safe_get_dict(_entries_for(bundle, domain), code)
    references = entry.get("see_also")
    if not isinstance(references, list):
        references = []
    see_also = ", ".join(value for value in references if isinstance(value, str))
    return _guide_row(code, "code", _guide_name(item["name"]), compact_range,
                      "see_also: " + see_also)


def render_guide_tsv(bundle):
    """Render the optional 0.7 routing hierarchy as an all-domain TSV.

    Area/category prose belongs in this greppable run artifact, not in every
    panel/advisor prompt. One record occupies one physical line; code records
    intentionally carry only their display name, compact severity range, and
    cross-references because criteria and rung conditions remain inline in the
    prompts. ``None`` preserves the 0.6 no-guide posture.
    """
    domains = _safe_get_dict(bundle, "domains")
    outlines = {domain: domain_outline(bundle, domain) for domain in domains}
    if not any(outlines.values()):
        return None

    rows = []
    for domain in sorted(domains):
        dom = _safe_get_dict(domains, domain)
        outline = outlines[domain] or {"guide": "", "areas": []}
        rows.append(_guide_row(domain, "domain", _guide_name(dom.get("name")),
                               outline["guide"]))
        menu = domain_menu(bundle, domain)
        groups, assigned = _guide_groups(menu, outline)
        for area in outline["areas"]:
            area_key = area["key"]
            rows.append(_guide_row("%s-%s" % (domain, area_key), "area",
                                   _guide_name(area["name"]), area["guide"]))
            for category in area["categories"]:
                category_key = category["key"]
                rows.append(_guide_row(
                    "%s-%s%s" % (domain, area_key, category_key),
                    "category", _guide_name(category["name"]), category["guide"]))
                rows.extend(
                    _guide_code_row(bundle, domain, item)
                    for item in groups.get((area_key, category_key), [])
                )

        # A newly added code must remain discoverable even if its hierarchy
        # metadata has not caught up yet.
        rows.extend(_guide_code_row(bundle, domain, item) for item in menu
                    if item["code"] not in assigned)
    return "\n".join(rows) + "\n"


def domain_menu(bundle, domain):
    """The domain's entries as [{code, name, severity, cwe}], sorted by code.
    [] for an unknown domain or a None/non-dict bundle."""
    if not isinstance(bundle, dict):
        return []
    entries = _entries_for(bundle, domain)
    menu = []
    for code in sorted(entries):
        entry = entries[code]
        if not isinstance(entry, dict):
            continue
        sev = entry.get("default_severity")
        item = {"code": code,
                "name": entry.get("name", ""),
                "severity": sev or _MENU_SEVERITY_WHEN_ABSENT,
                "cwe": entry.get("cwe") if isinstance(entry.get("cwe"), list) else []}
        if not sev:   # #1034: flag the assumed severity, never silently fabricate
            item["severity_assumed"] = True
        menu.append(item)
    return menu


def domain_criteria(bundle, domain):
    """The domain's entries that carry explicit `criteria` text, as
    [{code, name, criteria}], sorted by code. [] for an unknown domain, a
    None/non-dict bundle, or a domain whose entries have no criteria. The
    advisor's grading lens is gated per-code on criteria PRESENCE (#1035): a
    code without criteria is simply omitted and falls back to its menu
    one-liner."""
    if not isinstance(bundle, dict):
        return []
    entries = _entries_for(bundle, domain)
    out = []
    for code in sorted(entries):
        entry = entries[code]
        if not isinstance(entry, dict):
            continue
        crit = entry.get("criteria")
        if crit and isinstance(crit, str):
            out.append({"code": code, "name": entry.get("name", ""),
                        "criteria": crit})
    return out


def is_domain(name):
    """True iff `name` is one of the roster domains (ZZZ included).

    #1639 P15 fix round 2 (F1): the roster is `DOMAIN_TO_PANEL`'s keys and is
    ALSO the `candidates[].domain` enum in x0x-report-schema.json, so anything
    outside it is off-contract for a published artifact. One predicate, so the
    two call sites that had to invent the check cannot disagree with each other
    or with the roster.
    """
    return isinstance(name, str) and name in DOMAIN_TO_PANEL


def domain_prefix(code: str) -> str:
    """Raw text before the first hyphen; callers normalize and validate it."""
    return code.split("-", 1)[0]


def domain_of(code):
    """The domain prefix of a code ('SEC-A1A' -> 'SEC'), or None.

    PREFIX ONLY -- it says what the code claims, not whether the claim is a
    real domain. `is_domain` is that question, and a caller that puts this
    value into an artifact must ask it (F1: `"code": "CWE-798"` claims domain
    `CWE`, which is not a domain, and reached the X0X enum).
    """
    if not isinstance(code, str) or "-" not in code:
        return None
    return domain_prefix(code)


# The domain half of UNKNOWN_DOMAIN_FALLBACK, derived rather than retyped so the
# sentinel DOMAIN and the sentinel CODE cannot drift apart.
UNKNOWN_DOMAIN = domain_prefix(UNKNOWN_DOMAIN_FALLBACK)
_X0X_SUFFIX = "-X0X"


def is_fallback_code(code):
    """True iff `code` is a `<DOM>-X0X` catalog-gap fallback, in ANY case.

    #2236 (ARC-101960059): `x0x_report.is_fallback` matched the suffix
    case-SENSITIVELY and `strain_report._is_gap` upper-cased first, so `sec-x0x`
    was a catalog gap to one emitter and an ordinary code to the other. Codes
    arrive verbatim from the reviewer, with no case-fold upstream, so the split
    was reachable. One predicate, case-insensitive and whitespace-stripped like
    `domain_claim` -- the owner's two halves must not disagree about the same
    code, and `"SEC-X0X "` tolerated by one and not the other would file a
    catalog gap as an ordinary SEC finding (fix round 1, finding 7).
    """
    return bool(code) and str(code).strip().upper().endswith(_X0X_SUFFIX)


def domain_claim(value):
    """`value` as a domain CLAIM: stripped and upper-cased, nothing else.

    NOT validated -- `is_domain` is that question and `clamp_domain` is the
    answer that is safe to publish. Normalizing without clamping is its own
    need: two codes claiming two DIFFERENT off-roster domains are cross-domain
    strain, and comparing their clamped values would read both as
    `UNKNOWN_DOMAIN` and report "same domain" (fix round 1, finding 2). Case and
    stray whitespace are not a disagreement, which is why the comparison is this
    and not the raw `domain_of`.
    """
    return str(value).strip().upper()


def clamp_domain(claim, disclose=None):
    """The roster domain `claim` names, CLAMPED to `UNKNOWN_DOMAIN` when it is
    not one (`is_domain`). Takes a DOMAIN, not a code.

    TOTAL by construction, so the answer is always inside the `domain` enum both
    published gap artifacts pin -- x0x's `candidates[].domain` and strain's
    `signals[].domain` -- whatever a reviewer wrote. #2236: `x0x_report` clamped
    (#1639 P15 F1) and `strain_report` returned the prefix verbatim, which put an
    off-roster string into strain's published `domain` and decided its
    `cross_domain` flag.

    A caller holding a CODE wants `roster_domain`. Splitting the two questions is
    fix round 1, finding 1: a caller that has already resolved a claim must not
    have it re-split, or a hyphenated claim (`DAT-C1B`, `SEC-NOPE`) is silently
    reinterpreted as the domain before its first hyphen instead of clamped --
    and the disclosure disappears with it.

    `disclose`, when given, is called with the REJECTED claim as the clamp
    fires: a clamp rewrites a published value, so it is never silent, and each
    emitter owns the wording and the bounding of its own stderr line (the claim
    is agent-authored).
    """
    dom = domain_claim(claim)
    if is_domain(dom):
        return dom
    if disclose is not None:
        disclose(dom)
    return UNKNOWN_DOMAIN


def roster_domain(code, disclose=None):
    """`clamp_domain` of a CODE's domain prefix (`DAT-C1B` -> `DAT`)."""
    return clamp_domain(domain_prefix(str(code)), disclose)


def validate_code(bundle, code):
    """True iff `code` is a real entry in the bundle. A synthetic '<DOM>-X0X'
    fallback code is NOT a real entry (returns False) — that is the catalog-gap
    signal synthesize counts."""
    if not isinstance(bundle, dict) or not isinstance(code, str):
        return False
    dom = domain_of(code)
    if not dom:
        return False
    return code in _entries_for(bundle, dom)


def category_of(bundle, code):
    """The catalog's category name for a real entry ('SEC-A1A' -> area A, category 1), or None:
    a fallback code, or one the bundle has no entry for, names no category."""
    if not validate_code(bundle, code):
        return None
    dom = _safe_get_dict(_safe_get_dict(bundle, "domains"), domain_of(code))
    suffix = code.split("-", 1)[1]
    area = _safe_get_dict(_safe_get_dict(dom, "areas"), suffix[:1])
    name = _safe_get_dict(area, "categories").get(suffix[1:2])
    return name if isinstance(name, str) and name else None


def domain_fallback(domain):
    """The catalog-gap fallback code for a domain: '<DOM>-X0X'."""
    return "%s-X0X" % domain


def default_severity(bundle, code):
    """The default_severity for a code ('SEC-A1A' -> 'MEDIUM'), or None when the
    bundle is absent/malformed or the code is unknown."""
    if not isinstance(bundle, dict) or not isinstance(code, str):
        return None
    dom = domain_of(code)
    if not dom:
        return None
    entry = _entries_for(bundle, dom).get(code)
    if not isinstance(entry, dict):
        return None
    return entry.get("default_severity")
