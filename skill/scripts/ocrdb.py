"""Read access to the vendored OCRDb domain catalog — the 5.0 review-matrix
finding-code source. Pure: loads the pinned bundle and answers domain-menu /
code-validation queries. Tolerant degrade-to-None when the bundle is absent (the
review then runs code-less = 4.x behavior); a present-but-malformed bundle is a
LOUD ValueError, never a silent no-code run. Mirrors citations.load_cwe_catalog.
See docs/superpowers/specs/2026-08-15-panopticon-5.0-review-matrix-design.md §4.
"""
import json
import os

try:
    from scripts import _version
except ModuleNotFoundError:  # imported flat, with skill/scripts itself on sys.path
    import _version

BUNDLE_VERSION = "0.3.1"
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
# the pinned 0.3.1 bundle omit it, so this is latent — but any future entry that
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


def domain_menu(bundle, domain):
    """The domain's entries as [{code, name, severity, cwe}], sorted by code.
    [] for an unknown domain or a None/non-dict bundle."""
    if not isinstance(bundle, dict):
        return []
    dom = (bundle.get("domains") or {}).get(domain) or {}
    entries = dom.get("entries") or {}
    menu = []
    for code in sorted(entries):
        entry = entries[code] or {}
        sev = entry.get("default_severity")
        item = {"code": code,
                "name": entry.get("name", ""),
                "severity": sev or _MENU_SEVERITY_WHEN_ABSENT,
                "cwe": entry.get("cwe") or []}
        if not sev:   # #1034: flag the assumed severity, never silently fabricate
            item["severity_assumed"] = True
        menu.append(item)
    return menu


def domain_of(code):
    """The domain prefix of a code ('SEC-A1A' -> 'SEC'), or None."""
    if not isinstance(code, str) or "-" not in code:
        return None
    return code.split("-", 1)[0]


def validate_code(bundle, code):
    """True iff `code` is a real entry in the bundle. A synthetic '<DOM>-X0X'
    fallback code is NOT a real entry (returns False) — that is the catalog-gap
    signal synthesize counts."""
    if not isinstance(bundle, dict) or not code:
        return False
    dom = domain_of(code)
    if not dom:
        return False
    entries = ((bundle.get("domains") or {}).get(dom) or {}).get("entries") or {}
    return code in entries


def domain_fallback(domain):
    """The catalog-gap fallback code for a domain: '<DOM>-X0X'."""
    return "%s-X0X" % domain


def default_severity(bundle, code):
    """The default_severity for a code ('SEC-A1A' -> 'MEDIUM'), or None when the
    bundle is absent/malformed or the code is unknown."""
    if not isinstance(bundle, dict) or not code:
        return None
    dom = domain_of(code)
    if not dom:
        return None
    entry = ((bundle.get("domains") or {}).get(dom) or {}).get("entries", {}).get(code)
    if not isinstance(entry, dict):
        return None
    return entry.get("default_severity")
